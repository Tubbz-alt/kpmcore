/*************************************************************************
 *  Copyright 2017 by Andrius Štikonas <andrius@stikonas.eu>             *
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

//  SPDX-License-Identifier: GPL-3.0+


#include "helpers.h"
#include "backend/corebackendmanager.h"
#include "util/externalcommand.h"

#include <QCoreApplication>
#include <QDebug>
#include <QThread>

class runcmd : public QThread
{
    public:
    void run() override
    {
        ExternalCommand blkidCmd(QStringLiteral("blkid"), {});

        // ExternalCommadHelper will refuse to run this or any other command which is not whitelisted.
        // See src/util/externalcommand_whitelist.h for whitelisted commands.
        blkidCmd.run();
        qDebug().noquote() << blkidCmd.output();
    }
};

class runcmd2 : public QThread
{
    public:
    void run() override
    {
        ExternalCommand lsblkCmd(QStringLiteral("lsblk"), { QStringLiteral("--nodeps"), QStringLiteral("--json") });
        lsblkCmd.run();
        qDebug().noquote() << lsblkCmd.output();
    }
};


int main( int argc, char **argv )
{
    QCoreApplication app(argc, argv);
    KPMCoreInitializer i(QStringLiteral("pmsfdiskbackendplugin"));

    runcmd a;
    runcmd2 b;

    a.start();
    a.wait();

    b.start();
    b.wait();

    return 0;
}
