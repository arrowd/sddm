/***************************************************************************
* Copyright (c) 2021 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
* Copyright (c) 2013 Abdurrahman AVCI <abdurrahmanavci@gmail.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the
* Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
***************************************************************************/

#include <QDebug>
#include <QDir>
#include <QUuid>
#include <X11/Xauth.h>

#include "Configuration.h"
#include "Constants.h"
#include "XAuth.h"

#include <random>
#include <unistd.h>

#if !defined(HOST_NAME_MAX) && defined(_POSIX_HOST_NAME_MAX)
// On FreeBSD HOST_NAME_MAX is not defined, intentionally,
// to make applications use sysctl() to get real values .. let's not.
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

namespace SDDM {

XAuth::XAuth()
{
    m_authDir = QStringLiteral(RUNTIME_DIR);
}

QString XAuth::authDirectory() const
{
    return m_authDir;
}

void XAuth::setAuthDirectory(const QString &path)
{
    if (m_setup) {
        qWarning("Unable to set xauth directory after setup");
        return;
    }

    m_authDir = path;
}

QString XAuth::authPath() const
{
    return m_authPath;
}

QByteArray XAuth::cookie() const
{
    return m_cookie;
}

void XAuth::setup()
{
    if (m_setup)
        return;

    m_setup = true;

    // Create directory if not existing
    QDir().mkpath(m_authDir);

    // Set path
    m_authPath = QStringLiteral("%1/%2").arg(m_authDir).arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    qDebug() << "Xauthority path:" << m_authPath;

    // Generate cookie
    std::random_device rd;
    std::mt19937 gen(rd());
    // TODO: Vogtinator has
    // std::uniform_int_distribution<> dis(0, 0xFF);
    // here. What's correct?
    std::uniform_int_distribution<> dis(0, 15);

    m_cookie.reserve(16);

    for(int i = 0; i < 16; i++)
        m_cookie[i] = dis(gen);
}

bool XAuth::writeCookieToFile(const QString &display)
{
    if(display.size() < 2 || display[0] != QLatin1Char(':') || m_cookie.count() != 16)
        return false;

    // Truncate the file. We don't support merging like the xauth tool does.
    FILE * const authFp = fopen(qPrintable(m_authPath), "wb");
    if (authFp == nullptr)
        return false;

    char localhost[HOST_NAME_MAX + 1] = "";
    if (gethostname(localhost, HOST_NAME_MAX) < 0)
        strcpy(localhost, "localhost");

    ::Xauth auth = {};
    char cookieName[] = "MIT-MAGIC-COOKIE-1";

    // Skip the ':'
    QByteArray displayNumberUtf8 = display.midRef(1).toUtf8();

    auth.family = FamilyLocal;
    auth.address = localhost;
    auth.address_length = strlen(auth.address);
    auth.number = displayNumberUtf8.data();
    auth.number_length = displayNumberUtf8.size();
    auth.name = cookieName;
    auth.name_length = sizeof(cookieName) - 1;
    auth.data = const_cast<char*>(m_cookie.data());
    auth.data_length = m_cookie.count();

    if (XauWriteAuth(authFp, &auth) == 0) {
        fclose(authFp);
        return false;
    }

    // Write the same entry again, just with FamilyWild
    auth.family = FamilyWild;
    auth.address_length = 0;
    if (XauWriteAuth(authFp, &auth) == 0) {
        fclose(authFp);
        return false;
    }

    bool success = fflush(authFp) != EOF;

    fclose(authFp);

    return success;
}

bool XAuth::writeCookieToFile(const QString &display,
                              const QString &fileName,
                              const QByteArray& cookie) {
    XAuth auth;
    auth.m_cookie = cookie;
    auth.m_authPath = fileName;

    return auth.writeCookieToFile(display);
}

} // namespace SDDM
