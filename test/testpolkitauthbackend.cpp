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
**************************************************************************/
 
//  SPDX-License-Identifier: GPL-3.0+ 

#include "testpolkitauthbackend.h"
#include "util/externalcommand_polkitbackend.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDebug>
#include <QString>
#include <QTest>

#include <PolkitQt1/Authority>
#include <PolkitQt1/Subject>

using namespace Auth;
using namespace PolkitQt1;

TestPolkitAuthBackend::TestPolkitAuthBackend()
{
}

TestPolkitAuthBackend::~TestPolkitAuthBackend()
{
}

void TestPolkitAuthBackend::startHelper(const QString &action, const QString &helperID) const
{
    PolkitQt1Backend *m_authJob = new PolkitQt1Backend;
    m_authJob->startHelper(action, helperID);
}

void TestPolkitAuthBackend::initAgent(const QString &action, QWidget *parent/* = nullptr*/) const
{
    PolkitQt1Backend *m_authJob = new PolkitQt1Backend;
    m_authJob->initPolkitAgent(action, parent);
}

QByteArray TestPolkitAuthBackend::callerID() const
{
    return QByteArray("Random caller ID");
}

Authority::Result TestPolkitAuthBackend::actionStatus(const QString &action, const QByteArray &callerID) const
{
    SystemBusNameSubject subject(QString::fromUtf8(callerID));
    
    auto authority = PolkitQt1::Authority::instance();
    auto result = authority->checkAuthorizationSync(action, subject, Authority::None);
    
    return result;
}

bool TestPolkitAuthBackend::authorizeAction(const QString &action, const QByteArray &caller) const
{
    if (action == QLatin1String("doomed.to.fail")) {
        return false;
    } else if (action == QLatin1String("requires.auth")) {
        return true;
    } else if (action == QLatin1String("generates.error")) {
        return false;
    } else if (action == QLatin1String("always.authorized")) {
        return true;
    } else if (action.startsWith(QLatin1String("org.kde.externalcommand.init"))) {
        qDebug() << "Caller ID:" << callerID();
        const QByteArray calling = callerID();
        
        if (caller == calling) {
            return true;
        } else {
            return false;
        }
    }

    return false;
}

bool TestPolkitAuthBackend::revokeAuthorization(const QString &action, const QByteArray &callerID) const
{
    Q_UNUSED(action)
    
    SystemBusNameSubject subject(QString::fromUtf8(callerID));
    
    auto authority = Authority::instance();
    
    return authority->revokeTemporaryAuthorizationsSync(subject);
}

QTEST_MAIN(TestPolkitAuthBackend) 
