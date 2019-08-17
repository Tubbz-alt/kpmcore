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

#ifndef  KPMCORE_EXTERNALCOMMAND_POLKITBACKEND_H
#define  KPMCORE_EXTERNALCOMMAND_POLKITBACKEND_H

#include <QEventLoop>
#include <QHash>
#include <QObject>
#include <QString>
#include <QVariant>

#include <PolkitQt1/Authority>

using namespace PolkitQt1;

namespace Auth
{

/** A Polkit Qt backend class for authorizing actions.

    This class is used to authorize various actions if they
    ask for privileged execution. It starts by verifying the
    action under consideration if it is the one it is 
    saying and authorizes it based on the credentials 
    provided.

    @author Shubham <aryan100jangid@gmail.com>
**/
class PolkitQt1Backend : public QObject
{
  Q_OBJECT
  Q_DISABLE_COPY(PolkitQt1Backend)
  
public:
    /**
     * \brief Constructor of PolkitQt1Backend class
     */
    PolkitQt1Backend();
    
    /**
     * \brief Destructor of PolkitQt1Backend class
     */
   ~PolkitQt1Backend();
    
    /**
     * \brief Initializes the KDE Polkit Authentication Agent.
     * 
     * \param action Action in question
     * \param parent Parent widget
     *
     */
     void initPolkitAgent(const QString &action, QWidget *parent = nullptr) const;
    
    /**
     * \brief A function to check for the action's current status.
     * 
     * \param action Action in question
     * \param calledID The Application process ID  of the action
     *
     * \return the result of action status ie. If action is Authorized or not.
     */
     Authority::Result actionStatus(const QString &action, const QByteArray &callerID) const;
    
    /**
     * \brief Function to get the current Application process ID
     * 
     * \return Application process ID  of the action
     */                                         
     QByteArray callerID() const;
    
    /**
     * \brief Tries to authorize to the \p action in question.
     *
     * \param action Action in question.
     * \param callerID The Application process ID  of the action
     *
     * \return \c true if authority authorizes the action successfully, \c false Action is not authorized.
     *
    */
     bool authorizeAction(const QString &action, const QByteArray &callerID);
     
    /**
     * \brief Stops the running \p action from executing.
     *
     * \param action Action in question.
     *
    */
    bool revokeAuthorization(const QString &action, const QByteArray &callerID);

public Q_SLOTS:
    void authStatusChanged();
    
private:
    QHash<QString, Authority::Result> m_cachedResults;
    bool m_flyingActions; // Already running actions
};

/** A Polkit event loop class.

    This class is used to implement a polkit event
    loop and has the capability of returning the 
    current authorization result of the action in 
    que.
    
    @author Shubham <aryan100jangid@gmail.com>
**/
class PolkitEventLoop : public QEventLoop
{
  Q_OBJECT
  
public:
    PolkitEventLoop(QObject *parent = nullptr);
   ~PolkitEventLoop();
   
    Authority::Result result() const;
    
public:
    static Authority::Result m_result;
};

} // namespace Auth

#endif //  KPMCORE_EXTERNALCOMMAND_POLKITBACKEND_H  
