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

#ifndef TESTPOLKITAUTHBACKEND_H
#define TESTPOLKITAUTHBACKEND_H

#include <QObject>

#include <PolkitQt1/Authority>

class QByteArray;
class QString;

using namespace PolkitQt1;

class TestPolkitAuthBackend : public QObject
{
    Q_OBJECT

public:
    TestPolkitAuthBackend();
   ~TestPolkitAuthBackend();
   
private Q_SLOTS:
    void startHelper(const QString &action, const QString &helperID) const;
    void initAgent(const QString &action, QWidget *parent = nullptr) const;
    QByteArray callerID() const;
    Authority::Result actionStatus(const QString &action, const QByteArray &callerID) const;
    bool authorizeAction(const QString &action, const QByteArray &caller) const;
    bool revokeAuthorization(const QString &action, const QByteArray &callerID) const;
};

#endif // TESTPOLKITAUTHBACKEND_H 

