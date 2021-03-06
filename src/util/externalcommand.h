/*
    SPDX-FileCopyrightText: 2008-2010 Volker Lanz <vl@fidra.de>
    SPDX-FileCopyrightText: 2013-2020 Andrius Štikonas <andrius@stikonas.eu>
    SPDX-FileCopyrightText: 2015 Teo Mrnjavac <teo@kde.org>
    SPDX-FileCopyrightText: 2018 Huzaifa Faruqui <huzaifafaruqui@gmail.com>
    SPDX-FileCopyrightText: 2018 Harald Sitter <sitter@kde.org>
    SPDX-FileCopyrightText: 2019 Shubham Jangra <aryan100jangid@gmail.com>

    SPDX-License-Identifier: GPL-3.0-or-later
*/

#ifndef KPMCORE_EXTERNALCOMMAND_H
#define KPMCORE_EXTERNALCOMMAND_H

#include "util/libpartitionmanagerexport.h"

#include <QDebug>
#include <QProcess>
#include <QString>
#include <QStringList>
#include <QtGlobal>
#include <QThread>
#include <QVariant>

#include <memory>

namespace KAuth { class ExecuteJob; }

class KJob;
class Report;
class CopySource;
class CopyTarget;
class QDBusInterface;
class QDBusPendingCall;
class OrgKdeKpmcoreExternalcommandInterface;

struct ExternalCommandPrivate;

class DBusThread : public QThread
{
    Q_OBJECT
    // We register on DBus so the helper can monitor us and terminate if we
    // terminate.
    Q_CLASSINFO("D-Bus Interface", "org.kde.kpmcore.applicationinterface")
    void run() override;
};

/** An external command.

    Runs an external command as a child process.

    @author Volker Lanz <vl@fidra.de>
    @author Andrius Štikonas <andrius@stikonas.eu>
*/
class LIBKPMCORE_EXPORT ExternalCommand : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(ExternalCommand)

public:
    explicit ExternalCommand(const QString& cmd = QString(), const QStringList& args = QStringList(), const QProcess::ProcessChannelMode processChannelMode = QProcess::MergedChannels);
    explicit ExternalCommand(Report& report, const QString& cmd = QString(), const QStringList& args = QStringList(), const QProcess::ProcessChannelMode processChannelMode = QProcess::MergedChannels);

    ~ExternalCommand();

public:
    bool copyBlocks(const CopySource& source, CopyTarget& target);
    bool writeData(Report& commandReport, const QByteArray& buffer, const QString& deviceNode, const quint64 firstByte); // same as copyBlocks but from QByteArray
    bool createFile(const QByteArray& buffer, const QString& deviceNode); // similar to writeData but creates a new file

    /**< @param cmd the command to run */
    void setCommand(const QString& cmd);
     /**< @return the command to run */
    const QString& command() const;

    /**< @return the arguments */
    const QStringList& args() const;

    /**< @param s the argument to add */
    void addArg(const QString& s);
    /**< @param args the new arguments */
    void setArgs(const QStringList& args);

    bool write(const QByteArray& input); /**< @param input the input for the program */

    bool startCopyBlocks();
    bool start(int timeout = 30000);
    bool run(int timeout = 30000);

    /**< @return the exit code */
    int exitCode() const;

    /**< @return the command output */
    const QString output() const;
    /**< @return the command output */
    const QByteArray& rawOutput() const;

    /**< @return pointer to the Report or nullptr */
    Report* report();

    void emitReport(const QVariantMap& report) { Q_EMIT reportSignal(report); }

    // KAuth
    /**< start ExternalCommand Helper */
    bool startHelper();

    /**< stop ExternalCommand Helper */
    static void stopHelper();

    /**< Sets a parent widget for the authentication dialog.
     * @param p parent widget
     */
    static void setParentWidget(QWidget *p) {
        parent = p;
    }

Q_SIGNALS:
    void progress(int);
    void reportSignal(const QVariantMap&);

public Q_SLOTS:
    void emitProgress(KJob*, unsigned long percent) { Q_EMIT progress(percent); }

private:
    void setExitCode(int i);
    void onReadOutput();
    bool waitForDbusReply(QDBusPendingCall &pcall);
    OrgKdeKpmcoreExternalcommandInterface* helperInterface();

private:
    std::unique_ptr<ExternalCommandPrivate> d;

    // KAuth
    static KAuth::ExecuteJob *m_job;
    static bool helperStarted;
    static QWidget *parent;
};

#endif
