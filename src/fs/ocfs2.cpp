/*
    SPDX-FileCopyrightText: 2008-2010 Volker Lanz <vl@fidra.de>
    SPDX-FileCopyrightText: 2012-2018 Andrius Štikonas <andrius@stikonas.eu>
    SPDX-FileCopyrightText: 2015 Teo Mrnjavac <teo@kde.org>
    SPDX-FileCopyrightText: 2019 Yuri Chornoivan <yurchor@ukr.net>
    SPDX-FileCopyrightText: 2020 Arnaud Ferraris <arnaud.ferraris@collabora.com>
    SPDX-FileCopyrightText: 2020 Gaël PORTAY <gael.portay@collabora.com>

    SPDX-License-Identifier: GPL-3.0-or-later
*/

#include "fs/ocfs2.h"

#include "util/externalcommand.h"
#include "util/capacity.h"

#include <QRegularExpression>
#include <QString>

namespace FS
{
FileSystem::CommandSupportType ocfs2::m_GetUsed = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_GetLabel = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_Create = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_Grow = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_Shrink = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_Move = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_Check = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_Copy = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_Backup = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_SetLabel = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_UpdateUUID = FileSystem::cmdSupportNone;
FileSystem::CommandSupportType ocfs2::m_GetUUID = FileSystem::cmdSupportNone;

ocfs2::ocfs2(qint64 firstsector, qint64 lastsector, qint64 sectorsused, const QString& label, const QVariantMap& features) :
    FileSystem(firstsector, lastsector, sectorsused, label, features, FileSystem::Type::Ocfs2)
{
}

void ocfs2::init()
{
    m_Create = findExternal(QStringLiteral("mkfs.ocfs2"), { QStringLiteral("--version") }) ? cmdSupportFileSystem : cmdSupportNone;
    m_Check = findExternal(QStringLiteral("fsck.ocfs2"), {}, 16) ? cmdSupportFileSystem : cmdSupportNone;
    m_Grow = (m_Check != cmdSupportNone && findExternal(QStringLiteral("tunefs.ocfs2"), { QStringLiteral("--version") }) && findExternal(QStringLiteral("debugfs.ocfs2"), { QStringLiteral("--version") })) ? cmdSupportFileSystem : cmdSupportNone;
    m_Shrink = cmdSupportNone;

    // TODO: it seems there's no way to get the FS usage with ocfs2
    m_GetUsed = cmdSupportNone;

    m_SetLabel = findExternal(QStringLiteral("tunefs.ocfs2"), { QStringLiteral("--version") }) ? cmdSupportFileSystem : cmdSupportNone;
    m_UpdateUUID = findExternal(QStringLiteral("tunefs.ocfs2"), { QStringLiteral("--version") }) ? cmdSupportFileSystem : cmdSupportNone;

    m_Copy = (m_Check != cmdSupportNone) ? cmdSupportCore : cmdSupportNone;
    m_Move = (m_Check != cmdSupportNone) ? cmdSupportCore : cmdSupportNone;

    m_GetLabel = cmdSupportCore;
    m_Backup = cmdSupportCore;
    m_GetUUID = cmdSupportCore;
}

bool ocfs2::supportToolFound() const
{
    return
//          m_GetUsed != cmdSupportNone &&
        m_GetLabel != cmdSupportNone &&
        m_SetLabel != cmdSupportNone &&
        m_Create != cmdSupportNone &&
        m_Check != cmdSupportNone &&
        m_UpdateUUID != cmdSupportNone &&
        m_Grow != cmdSupportNone &&
//          m_Shrink != cmdSupportNone &&
        m_Copy != cmdSupportNone &&
        m_Move != cmdSupportNone &&
        m_Backup != cmdSupportNone &&
        m_GetUUID != cmdSupportNone;
}

FileSystem::SupportTool ocfs2::supportToolName() const
{
    return SupportTool(QStringLiteral("ocfs2-tools"), QUrl(QStringLiteral("https://oss.oracle.com/projects/ocfs2-tools/")));
}

qint64 ocfs2::minCapacity() const
{
    return 14000 * Capacity::unitFactor(Capacity::Unit::Byte, Capacity::Unit::KiB);
}

qint64 ocfs2::maxCapacity() const
{
    return 4 * Capacity::unitFactor(Capacity::Unit::Byte, Capacity::Unit::PiB);
}

qint64 ocfs2::readUsedCapacity(const QString& deviceNode) const
{
    Q_UNUSED(deviceNode)
    return -1;
}

bool ocfs2::check(Report& report, const QString& deviceNode) const
{
    ExternalCommand cmd(report, QStringLiteral("fsck.ocfs2"), { QStringLiteral("-f"), QStringLiteral("-y"), deviceNode });
    return cmd.run(-1) && (cmd.exitCode() == 0 || cmd.exitCode() == 1 || cmd.exitCode() == 2);
}

bool ocfs2::create(Report& report, const QString& deviceNode)
{
    ExternalCommand cmd(report, QStringLiteral("mkfs.ocfs2"), { deviceNode });

    cmd.write("y\n");
    if (!cmd.start())
        return false;

    return cmd.exitCode() == 0;

}

bool ocfs2::resize(Report& report, const QString& deviceNode, qint64 length) const
{
    ExternalCommand cmdBlockSize(QStringLiteral("debugfs.ocfs2"), { QStringLiteral("--request"), QStringLiteral("stats"), deviceNode });

    qint32 blockSize = -1;
    if (cmdBlockSize.run(-1) && cmdBlockSize.exitCode() == 0) {
        QRegularExpression re(QStringLiteral("Block Size Bits: (\\d+)"));
        QRegularExpressionMatch reBlockSizeBits = re.match(cmdBlockSize.output());

        if (reBlockSizeBits.hasMatch())
            blockSize = 1 << reBlockSizeBits.captured(1).toInt();
    }

    if (blockSize == -1)
        return false;

    ExternalCommand cmd(report, QStringLiteral("tunefs.ocfs2"), { QStringLiteral("--yes"), QStringLiteral("--volume-size"), deviceNode, QString::number(length / blockSize) });
    return cmd.run(-1) && cmd.exitCode() == 0;
}

bool ocfs2::writeLabel(Report& report, const QString& deviceNode, const QString& newLabel)
{
    ExternalCommand cmd(report, QStringLiteral("tunefs.ocfs2"), { QStringLiteral("--label"), newLabel, deviceNode });
    return cmd.run(-1) && cmd.exitCode() == 0;
}

bool ocfs2::updateUUID(Report& report, const QString& deviceNode) const
{
    ExternalCommand cmd(report, QStringLiteral("tunefs.ocfs2"), { QStringLiteral("--uuid-reset"), deviceNode });
    return cmd.run(-1) && cmd.exitCode() == 0;
}
}
