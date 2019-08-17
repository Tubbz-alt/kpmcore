/*************************************************************************
 *  Copyright (C) 2019 by Shubham <aryan100jangid@gmail.com>             *    
 *                                                                       *
 *  This program is free software; you can redistribute it and/or        *
 *  modify it under the terms of the GNU General Public License as       *
 *  published by the Free Software Foundation; either version 3 of       *
 *  the License, or (at your option) any later version.                  *
 *                                                                       *
 *  This program is distributed in the hope that it will be useful,      *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *  GNU General Public License for more details.                         *
 *                                                                       *
 *  You should have received a copy of the GNU General Public License    *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.*
 *************************************************************************/
 
#include "util/externalcommand_polkitbackend.h"

#include <QApplication>
#include <QDebug>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QEventLoop>
#include <QString>
#include <QTimer>
#include <QWidget>

#include <PolkitQt1/Authority>
#include <PolkitQt1/Subject>

using namespace PolkitQt1;

Authority::Result Auth::PolkitEventLoop::m_result = Authority::No;

namespace Auth
{
    
PolkitEventLoop::PolkitEventLoop(QObject *parent)
            : QEventLoop(qobject_cast<QEventLoop *>(parent))
{
    
}

PolkitEventLoop::~PolkitEventLoop()
{
    
}

Authority::Result PolkitEventLoop::result() const
{
    return m_result;
}

PolkitQt1Backend::PolkitQt1Backend()
            : m_flyingActions(false)
{
    // Connect various useful Polkit signals
    connect(Authority::instance(), &Authority::configChanged, this, &Auth::PolkitQt1Backend::authStatusChanged);
    connect(Authority::instance(), &Authority::consoleKitDBChanged, this, &Auth::PolkitQt1Backend::authStatusChanged); 

    m_flyingActions = true;
}

PolkitQt1Backend::~PolkitQt1Backend()
{
    
}
    
void PolkitQt1Backend::initPolkitAgent(const QString &action, QWidget *parent /*= nullptr*/) const
{
    if (!parent) {
        qWarning() << "Parent widget does not exists, can not proceed further";
        return;
    }
    
    // Check if we are running terminal session or GUI session
    if (!qApp) {
        qWarning() << "We are running a TTY (Terminal) session";
        qDebug() << "Can not proceed further since we do not support Text based Polkit Authentication Agent";
        return;
    }

    // Get the dialog parent window Id
    quint64 parentWindowID = parent->effectiveWinId();
    
    // Make a call to the KDE polkit Authentication Agent asking for it's services
    QDBusMessage callAgent = QDBusMessage::createMethodCall(QLatin1String("org.kde.polkit-kde-authentication-agent-1"), QLatin1String("/org/kde/Polkit1AuthAgent"), QLatin1String("org.kde.Polkit1AuthAgent"),
                                                            QLatin1String("setWIdForAction"));

    callAgent << action;
    callAgent << parentWindowID;

    QDBusPendingCall call = QDBusConnection::sessionBus().asyncCall(callAgent);
    
    auto watcher = new QDBusPendingCallWatcher(call);

    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, action, watcher](){
        watcher->deleteLater();
        const QDBusMessage reply = watcher->reply();
        
        if (reply.type() == QDBusMessage::ErrorMessage) {
            qWarning() << "Could not call the Authentication Agent, Error:" << reply.errorMessage();
        }
    });
}

Authority::Result PolkitQt1Backend::actionStatus(const QString &action, const QByteArray &callerID) const
{
    SystemBusNameSubject subject(QString::fromUtf8(callerID));
    
    auto authority = Authority::instance();
    
    PolkitEventLoop::m_result = authority->checkAuthorizationSync(action, subject, Authority::AllowUserInteraction);

    if (authority->hasError()) {
        qDebug() << "Encountered error while checking action status, Error code:" << authority->lastError() << "\n";
        qDebug() << "Error Details:" << authority->errorDetails();
        authority->clearError();
    }

    return PolkitEventLoop::m_result;
}

QByteArray PolkitQt1Backend::callerID() const
{
    return QDBusConnection::systemBus().baseService().toUtf8();
}

bool PolkitQt1Backend::authorizeAction(const QString &action, const QByteArray &callerID)
{
    // Set m_result here, otherwise there will be wrong log message displayed inside externalcommand.cpp line 383
    
    SystemBusNameSubject subject(QString::fromUtf8(callerID));
    
    auto authority = Authority::instance();

    PolkitEventLoop event;
    event.processEvents();
    
    connect(authority, &Authority::checkAuthorizationFinished, &event, &PolkitEventLoop::quit);
    authority->checkAuthorization(action, subject, Authority::AllowUserInteraction);
    
    event.exec();

    if (authority->hasError()) {
        qWarning() << "Encountered error while checking authorization, Error code:" << authority->lastError() << "\n";
        qDebug() << "Error details:" << authority->errorDetails();
        
        // Clear all the errors from the buffer so that hasError() does not give previous error as a result when called later
        authority->clearError();
    }
    
    if (/*event.result()*/ /*PolkitEventLoop::m_result*/ actionStatus(action, callerID) == Authority::Yes) {
        return true;
    } else {
        return false;
    }
}

bool PolkitQt1Backend::revokeAuthorization(const QString &action, const QByteArray &callerID)
{
    Q_UNUSED(action)
    
    SystemBusNameSubject subject(QString::fromUtf8(callerID));
    
    auto authority = Authority::instance();
    
    return authority->revokeTemporaryAuthorizationsSync(subject);
}

void PolkitQt1Backend::authStatusChanged()
{
    for (auto it = m_cachedResults.begin(); it != m_cachedResults.end(); ++it) {
        const QString action = it.key();
        QByteArray pid = QDBusConnection::systemBus().baseService().toUtf8();
        if (it.value() != actionStatus(action, pid)) {
            *it = actionStatus(action, pid);
        }
    }

    // Force updating known actions
    Authority::instance()->enumerateActions();
    m_flyingActions = true;
}

} // namespace Auth  
