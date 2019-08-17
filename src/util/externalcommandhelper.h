/*************************************************************************
 *  Copyright (C) 2017-2018 by Andrius Štikonas <andrius@stikonas.eu>    *
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

#ifndef KPMCORE_EXTERNALCOMMANDHELPER_H
#define KPMCORE_EXTERNALCOMMANDHELPER_H

#include <memory>
#include <unordered_set>

#include <QEventLoop>
#include <QProcess>
#include <QString>
#include <QVariant>

#define HELPER_MAIN() \
    int main(int argc, char **argv) { ExternalCommandHelper helper; return helper.helperMain(argc, argv); }

class ExternalCommandHelper : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.kde.kpmcore.externalcommand")
    
public:
    bool readData(const QString& sourceDevice, QByteArray& buffer, const qint64 offset, const qint64 size);
    bool writeData(const QString& targetDevice, const QByteArray& buffer, const qint64 offset);
    void sendProgress(int percent);
    void sendProgress(QString message);
    int helperMain(int argc, char **argv);
    
public Q_SLOTS:
    Q_SCRIPTABLE QVariantMap start(const QString& command, const QStringList& arguments, const QByteArray& input, const int processChannelMode);
    Q_SCRIPTABLE QVariantMap copyblocks(const QString& sourceDevice, const qint64 sourceFirstByte, const qint64 sourceLength, const QString& targetDevice, const qint64 targetFirstByte, const qint64 blockSize);
    Q_SCRIPTABLE bool writeData(const QByteArray& buffer, const QString& targetDevice, const qint64 targetFirstByte);
    Q_SCRIPTABLE void exit();

private:
    std::unique_ptr<QEventLoop> m_loop;
    QProcess m_cmd;
    
//  QByteArray output;
//  void onReadOutput();    
};

#endif // KPMCORE_EXTERNALCOMMANDHELPER_H
