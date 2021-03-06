/*
    SPDX-FileCopyrightText: 2008-2010 Volker Lanz <vl@fidra.de>
    SPDX-FileCopyrightText: 2013-2020 Andrius Štikonas <andrius@stikonas.eu>
    SPDX-FileCopyrightText: 2015 Teo Mrnjavac <teo@kde.org>
    SPDX-FileCopyrightText: 2016 Chantara Tith <tith.chantara@gmail.com>
    SPDX-FileCopyrightText: 2018 Huzaifa Faruqui <huzaifafaruqui@gmail.com>
    SPDX-FileCopyrightText: 2018 Caio Jordão Carvalho <caiojcarvalho@gmail.com>
    SPDX-FileCopyrightText: 2019 Shubham Jangra <aryan100jangid@gmail.com>
    SPDX-FileCopyrightText: 2019 Yuri Chornoivan <yurchor@ukr.net>

    SPDX-License-Identifier: GPL-3.0-or-later
*/

#include "util/externalcommand.h"
#include "backend/corebackendmanager.h"
#include "core/device.h"
#include "core/copysource.h"
#include "core/copytarget.h"
#include "core/copytargetbytearray.h"
#include "core/copysourcedevice.h"
#include "core/copytargetdevice.h"
#include "util/globallog.h"
#include "util/report.h"

#include "externalcommandhelper_interface.h"

#include <QCryptographicHash>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QEventLoop>
#include <QtGlobal>
#include <QStandardPaths>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QThread>
#include <QVariant>

#include <KAuth>
#include <KJob>
#include <KLocalizedString>

struct ExternalCommandPrivate
{
    Report *m_Report;
    QString m_Command;
    QStringList m_Args;
    int m_ExitCode;
    QByteArray m_Output;
    QByteArray m_Input;
    DBusThread *m_thread;
    QProcess::ProcessChannelMode processChannelMode;
};

KAuth::ExecuteJob* ExternalCommand::m_job;
bool ExternalCommand::helperStarted = false;
QWidget* ExternalCommand::parent;


/** Creates a new ExternalCommand instance without Report.
    @param cmd the command to run
    @param args the arguments to pass to the command
*/
ExternalCommand::ExternalCommand(const QString& cmd, const QStringList& args, const QProcess::ProcessChannelMode processChannelMode) :
    d(std::make_unique<ExternalCommandPrivate>())
{
    d->m_Report = nullptr;
    d->m_Command = cmd;
    d->m_Args = args;
    d->m_ExitCode = -1;
    d->m_Output = QByteArray();

    if (!helperStarted)
        if(!startHelper())
            Log(Log::Level::error) << xi18nc("@info:status", "Could not obtain administrator privileges.");

    d->processChannelMode = processChannelMode;
}

/** Creates a new ExternalCommand instance with Report.
    @param report the Report to write output to.
    @param cmd the command to run
    @param args the arguments to pass to the command
 */
ExternalCommand::ExternalCommand(Report& report, const QString& cmd, const QStringList& args, const QProcess::ProcessChannelMode processChannelMode) :
    d(std::make_unique<ExternalCommandPrivate>())
{
    d->m_Report = report.newChild();
    d->m_Command = cmd;
    d->m_Args = args;
    d->m_ExitCode = -1;
    d->m_Output = QByteArray();

    d->processChannelMode = processChannelMode;
}

ExternalCommand::~ExternalCommand()
{
    
}

/*
void ExternalCommand::setup()
{
     connect(this, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, &ExternalCommand::onFinished);
     connect(this, &ExternalCommand::readyReadStandardOutput, this, &ExternalCommand::onReadOutput);
}
*/

/** Executes the external command.
    @param timeout timeout to wait for the process to start
    @return true on success
*/
bool ExternalCommand::start(int timeout)
{
    Q_UNUSED(timeout)

    if (command().isEmpty())
        return false;

    if (report())
        report()->setCommand(xi18nc("@info:status", "Command: %1 %2", command(), args().join(QStringLiteral(" "))));

    if ( qEnvironmentVariableIsSet( "KPMCORE_DEBUG" ))
        qDebug() << xi18nc("@info:status", "Command: %1 %2", command(), args().join(QStringLiteral(" ")));

    QString cmd = QStandardPaths::findExecutable(command());
    if (cmd.isEmpty())
        cmd = QStandardPaths::findExecutable(command(), { QStringLiteral("/sbin/"), QStringLiteral("/usr/sbin/"), QStringLiteral("/usr/local/sbin/") });

    auto interface = helperInterface();
    if (!interface)
        return false;

    bool rval = false;

    QDBusPendingCall pcall = interface->start(cmd, args(), d->m_Input, d->processChannelMode);

    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(pcall, this);
    QEventLoop loop;

    auto exitLoop = [&] (QDBusPendingCallWatcher *watcher) {
        loop.exit();

        if (watcher->isError())
            qWarning() << watcher->error();
        else {
            QDBusPendingReply<QVariantMap> reply = *watcher;

            d->m_Output = reply.value()[QStringLiteral("output")].toByteArray();
            setExitCode(reply.value()[QStringLiteral("exitCode")].toInt());
            rval = reply.value()[QStringLiteral("success")].toBool();
        }
    };

    connect(watcher, &QDBusPendingCallWatcher::finished, exitLoop);
    loop.exec();

    return rval;
}

bool ExternalCommand::copyBlocks(const CopySource& source, CopyTarget& target)
{
    bool rval = true;
    const qint64 blockSize = 10 * 1024 * 1024; // number of bytes per block to copy

    // TODO KF6:Use new signal-slot syntax
    connect(m_job, SIGNAL(percent(KJob*, unsigned long)), this, SLOT(emitProgress(KJob*, unsigned long)));
    connect(m_job, &KAuth::ExecuteJob::newData, this, &ExternalCommand::emitReport);

    auto interface = helperInterface();
    if (!interface)
        return false;

    QDBusPendingCall pcall = interface->copyblocks(source.path(), source.firstByte(), source.length(),
                                                   target.path(), target.firstByte(), blockSize);

    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(pcall, this);
    QEventLoop loop;

    auto exitLoop = [&] (QDBusPendingCallWatcher *watcher) {
        loop.exit();
        if (watcher->isError())
            qWarning() << watcher->error();
        else {
            QDBusPendingReply<QVariantMap> reply = *watcher;
            rval = reply.value()[QStringLiteral("success")].toBool();

            CopyTargetByteArray *byteArrayTarget = dynamic_cast<CopyTargetByteArray*>(&target);
            if (byteArrayTarget)
                byteArrayTarget->m_Array = reply.value()[QStringLiteral("targetByteArray")].toByteArray();
        }
        setExitCode(!rval);
    };

    connect(watcher, &QDBusPendingCallWatcher::finished, exitLoop);
    loop.exec();

    return rval;
}

bool ExternalCommand::writeData(Report& commandReport, const QByteArray& buffer, const QString& deviceNode, const quint64 firstByte)
{
    d->m_Report = commandReport.newChild();
    if (report())
        report()->setCommand(xi18nc("@info:status", "Command: %1 %2", command(), args().join(QStringLiteral(" "))));

    auto interface = helperInterface();
    if (!interface)
        return false;

    QDBusPendingCall pcall = interface->writeData(buffer, deviceNode, firstByte);
    return waitForDbusReply(pcall);
}

bool ExternalCommand::createFile(const QByteArray& buffer, const QString& deviceNode)
{
    auto interface = helperInterface();
    if (!interface)
        return false;

    QDBusPendingCall pcall = interface->createFile(buffer, deviceNode);
    return waitForDbusReply(pcall);
}

OrgKdeKpmcoreExternalcommandInterface* ExternalCommand::helperInterface()
{
    if (!QDBusConnection::systemBus().isConnected()) {
        qWarning() << QDBusConnection::systemBus().lastError().message();
        return nullptr;
    }

    auto *interface = new org::kde::kpmcore::externalcommand(QStringLiteral("org.kde.kpmcore.externalcommand"),
                QStringLiteral("/Helper"), QDBusConnection::systemBus(), this);
    interface->setTimeout(10 * 24 * 3600 * 1000); // 10 days
    return interface;
}

bool ExternalCommand::waitForDbusReply(QDBusPendingCall &pcall)
{
    bool rval = true;
    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(pcall, this);
    QEventLoop loop;

    auto exitLoop = [&] (QDBusPendingCallWatcher *watcher) {
        loop.exit();
        if (watcher->isError())
            qWarning() << watcher->error();
        else {
            QDBusPendingReply<bool> reply = *watcher;
            rval = reply.argumentAt<0>();
        }
        setExitCode(!rval);
    };

    connect(watcher, &QDBusPendingCallWatcher::finished, exitLoop);
    loop.exec();

    return rval;
}

bool ExternalCommand::write(const QByteArray& input)
{
    if ( qEnvironmentVariableIsSet( "KPMCORE_DEBUG" ))
        qDebug() << "Command input:" << QString::fromLocal8Bit(input);
    d->m_Input = input;
    return true;
}

/** Runs the command.
    @param timeout timeout to use for waiting when starting and when waiting for the process to finish
    @return true on success
*/
bool ExternalCommand::run(int timeout)
{
    return start(timeout) /* && exitStatus() == 0*/;
}

void ExternalCommand::onReadOutput()
{
//     const QByteArray s = readAllStandardOutput();
//
//     if(m_Output.length() > 10*1024*1024) { // prevent memory overflow for badly corrupted file systems
//         if (report())
//             report()->line() << xi18nc("@info:status", "(Command is printing too much output)");
//         return;
//     }
//
//     m_Output += s;
//
//     if (report())
//         *report() << QString::fromLocal8Bit(s);
}

void ExternalCommand::setCommand(const QString& cmd)
{
    d->m_Command = cmd;
}

const QString& ExternalCommand::command() const
{
    return d->m_Command;
}

const QStringList& ExternalCommand::args() const
{
    return d->m_Args;
}

void ExternalCommand::addArg(const QString& s)
{
    d->m_Args << s;
}

void ExternalCommand::setArgs(const QStringList& args)
{
    d->m_Args = args;
}

int ExternalCommand::exitCode() const
{
    return d->m_ExitCode;
}

const QString ExternalCommand::output() const
{
    return QString::fromLocal8Bit(d->m_Output);
}

const QByteArray& ExternalCommand::rawOutput() const
{
    return d->m_Output;
}

Report* ExternalCommand::report()
{
    return d->m_Report;
}

void ExternalCommand::setExitCode(int i)
{
    d->m_ExitCode = i;
}

bool ExternalCommand::startHelper()
{
    if (!QDBusConnection::systemBus().isConnected()) {
        qWarning() << QDBusConnection::systemBus().lastError().message();
        return false;
    }
    
    QDBusInterface iface(QStringLiteral("org.kde.kpmcore.helperinterface"), QStringLiteral("/Helper"), QStringLiteral("org.kde.kpmcore.externalcommand"), QDBusConnection::systemBus());
    if (iface.isValid()) {
        exit(0);
    }

    d->m_thread = new DBusThread;
    d->m_thread->start();

    KAuth::Action action = KAuth::Action(QStringLiteral("org.kde.kpmcore.externalcommand.init"));
    action.setHelperId(QStringLiteral("org.kde.kpmcore.externalcommand"));
    action.setTimeout(10 * 24 * 3600 * 1000); // 10 days
    action.setParentWidget(parent);
    QVariantMap arguments;
    action.setArguments(arguments);
    m_job = action.execute();
    m_job->start();

    // Wait until ExternalCommand Helper is ready (helper sends newData signal just before it enters event loop)
    QEventLoop loop;
    auto exitLoop = [&] () { loop.exit(); };
    auto conn = QObject::connect(m_job, &KAuth::ExecuteJob::newData, exitLoop);
    QObject::connect(m_job, &KJob::finished, [=] () { if(m_job->error()) exitLoop(); } );
    loop.exec();
    QObject::disconnect(conn);

    helperStarted = true;
    return true;
}

void ExternalCommand::stopHelper()
{
    auto *interface = new org::kde::kpmcore::externalcommand(QStringLiteral("org.kde.kpmcore.externalcommand"),
                                                             QStringLiteral("/Helper"), QDBusConnection::systemBus());
    interface->exit();

}

void DBusThread::run()
{
    if (!QDBusConnection::systemBus().registerService(QStringLiteral("org.kde.kpmcore.applicationinterface")) || 
        !QDBusConnection::systemBus().registerObject(QStringLiteral("/Application"), this, QDBusConnection::ExportAllSlots)) {
        qWarning() << QDBusConnection::systemBus().lastError().message();
        return;
    }
        
    QEventLoop loop;
    loop.exec();
}
