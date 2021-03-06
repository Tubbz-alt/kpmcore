/*
    SPDX-FileCopyrightText: 2008-2010 Volker Lanz <vl@fidra.de>
    SPDX-FileCopyrightText: 2014-2016 Andrius Štikonas <andrius@stikonas.eu>
    SPDX-FileCopyrightText: 2015 Chris Campbell <c.j.campbell@ed.ac.uk>
    SPDX-FileCopyrightText: 2018 Caio Jordão Carvalho <caiojcarvalho@gmail.com>

    SPDX-License-Identifier: GPL-3.0-or-later
*/

#ifndef KPMCORE_RESIZEOPERATION_H
#define KPMCORE_RESIZEOPERATION_H

#include "util/libpartitionmanagerexport.h"

#include "ops/operation.h"

#include "core/partition.h"

#include <QString>

class Device;
class OperationStack;
class Report;

class CheckFileSystemJob;
class SetPartGeometryJob;
class ResizeFileSystemJob;
class SetPartGeometryJob;
class SetPartGeometryJob;
class MoveFileSystemJob;
class ResizeFileSystemJob;
class CheckFileSystemJob;

/** Resizes a Partition and FileSystem.

    Resize the given Partition and its FileSystem on the given Device so they start with the
    given new start sector and end with the given new last sector.

    @author Volker Lanz <vl@fidra.de>
*/
class LIBKPMCORE_EXPORT ResizeOperation : public Operation
{
    friend class OperationStack;

    Q_DISABLE_COPY(ResizeOperation)

protected:
    /** A ResizeOperation can do a combination of things; this enum is used to determine what
    actually is going to be done. It is used so the ResizeOperation can describe itself and
    when it's actually executed. */
    enum ResizeAction {
        None = 0,               /**< Nothing */
        MoveLeft = 1,           /**< Move to the left */
        MoveRight = 2,          /**< Move to the right */
        Grow = 4,               /**< Grow */
        Shrink = 8,             /**< Shrink */
        MoveLeftGrow = 5,       /**< Move to the left then grow */
        MoveRightGrow = 6,      /**< Move to the right then grow */
        MoveLeftShrink = 9,     /**< Shrink then move to the left */
        MoveRightShrink = 10    /**< Shrink then move to the right */
    };

public:
    ResizeOperation(Device& d, Partition& p, qint64 newfirst, qint64 newlast);

public:
    QString iconName() const override {
        return QStringLiteral("arrow-right-double");
    }
    QString description() const override;
    bool execute(Report& parent) override;
    void preview() override;
    void undo() override;

    bool targets(const Device& d) const override;
    bool targets(const Partition& p) const override;

    static bool canGrow(const Partition* p);
    static bool canShrink(const Partition* p);
    static bool canMove(const Partition* p);

protected:
    Device& targetDevice() {
        return m_TargetDevice;
    }
    const Device& targetDevice() const {
        return m_TargetDevice;
    }

    Partition& partition() {
        return m_Partition;
    }
    const Partition& partition() const {
        return m_Partition;
    }

    bool shrink(Report& report);
    bool move(Report& report);
    bool grow(Report& report);

    ResizeAction resizeAction() const;

    qint64 origFirstSector() const {
        return m_OrigFirstSector;
    }
    qint64 origLastSector() const {
        return m_OrigLastSector;
    }
    qint64 origLength() const {
        return origLastSector() - origFirstSector() + 1;
    }

    qint64 newFirstSector() const {
        return m_NewFirstSector;
    }
    qint64 newLastSector() const {
        return m_NewLastSector;
    }
    qint64 newLength() const {
        return newLastSector() - newFirstSector() + 1;
    }

    CheckFileSystemJob* checkOriginalJob() {
        return m_CheckOriginalJob;
    }
    SetPartGeometryJob* moveExtendedJob() {
        return m_MoveExtendedJob;
    }
    ResizeFileSystemJob* shrinkResizeJob() {
        return m_ShrinkResizeJob;
    }
    SetPartGeometryJob* shrinkSetGeomJob() {
        return m_ShrinkSetGeomJob;
    }
    SetPartGeometryJob* moveSetGeomJob() {
        return m_MoveSetGeomJob;
    }
    MoveFileSystemJob* moveFileSystemJob() {
        return m_MoveFileSystemJob;
    }
    ResizeFileSystemJob* growResizeJob() {
        return m_GrowResizeJob;
    }
    SetPartGeometryJob* growSetGeomJob() {
        return m_GrowSetGeomJob;
    }
    CheckFileSystemJob* checkResizedJob() {
        return m_CheckResizedJob;
    }

private:
    static bool isLVMPVinNewlyVG(const Partition* p);

private:
    Device& m_TargetDevice;
    Partition& m_Partition;
    const qint64 m_OrigFirstSector;
    const qint64 m_OrigLastSector;
    qint64 m_NewFirstSector;
    qint64 m_NewLastSector;
    CheckFileSystemJob* m_CheckOriginalJob;
    SetPartGeometryJob* m_MoveExtendedJob;
    ResizeFileSystemJob* m_ShrinkResizeJob;
    SetPartGeometryJob* m_ShrinkSetGeomJob;
    SetPartGeometryJob* m_MoveSetGeomJob;
    MoveFileSystemJob* m_MoveFileSystemJob;
    ResizeFileSystemJob* m_GrowResizeJob;
    SetPartGeometryJob* m_GrowSetGeomJob;
    CheckFileSystemJob* m_CheckResizedJob;
};

#endif
