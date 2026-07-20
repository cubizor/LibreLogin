/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.common.listener;

import java.util.Locale;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import xyz.kyngs.librelogin.api.database.User;
import xyz.kyngs.librelogin.api.event.events.AuthenticatedEvent;
import xyz.kyngs.librelogin.api.event.events.WrongPasswordEvent;
import xyz.kyngs.librelogin.api.event.events.WrongPasswordEvent.AuthenticationSource;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.config.ConfigurationKeys;

public class LoginTryListener<P, S> {

    private final AuthenticLibreLogin<P, S> plugin;
    private final Cache<String, Integer> loginTries;
    /**
     * Maps a tracking key to the epoch millis at which its ban expires. Held in memory only;
     * bans are lost on restart, which is acceptable for the short durations this is meant for.
     */
    private final Cache<String, Long> bans;
    private final boolean banByIP;
    private final int banSeconds;

    public LoginTryListener(AuthenticLibreLogin<P, S> libreLogin) {
        this.plugin = libreLogin;
        this.banByIP = plugin.getConfiguration().get(ConfigurationKeys.LOGIN_ATTEMPTS_BAN_BY_IP);
        this.banSeconds = plugin.getConfiguration().get(ConfigurationKeys.LOGIN_ATTEMPTS_BAN_SECONDS);
        this.loginTries = Caffeine.newBuilder()
                .expireAfterAccess(plugin.getConfiguration().get(ConfigurationKeys.MILLISECONDS_TO_EXPIRE_LOGIN_ATTEMPTS), TimeUnit.MILLISECONDS)
                .build();
        this.bans = Caffeine.newBuilder()
                // Guard against a non-positive duration; Caffeine rejects it, and the value is
                // unused anyway because banning is disabled in that case.
                .expireAfterWrite(Math.max(banSeconds, 1), TimeUnit.SECONDS)
                .build();
        libreLogin.getEventProvider().subscribe(libreLogin.getEventTypes().wrongPassword, this::onWrongPassword);
        libreLogin.getEventProvider().subscribe(libreLogin.getEventTypes().authenticated, this::onAuthenticated);
    }

    /**
     * Builds the key both login attempts and bans are tracked under. Tracking by IP is what
     * actually stops a brute-force attack; tracking by name lets the attacker reset their quota
     * by switching nicknames, but avoids locking out players who share an IP address.
     */
    public String trackingKey(String ip, String username) {
        return banByIP ? ip : username.toLowerCase(Locale.ROOT);
    }

    /**
     * @return the seconds remaining on the key's ban, or 0 if it is not banned
     */
    public long getRemainingBanSeconds(String key) {
        if (!banEnabled()) return 0;

        var expiresAt = bans.getIfPresent(key);
        if (expiresAt == null) return 0;

        var remaining = expiresAt - System.currentTimeMillis();
        if (remaining <= 0) {
            bans.invalidate(key);
            return 0;
        }

        // Round up, so that a sub-second remainder never renders as "0 seconds".
        return (remaining + 999) / 1000;
    }

    private boolean banEnabled() {
        return banSeconds > 0;
    }

    private void onWrongPassword(WrongPasswordEvent<P, S> wrongPasswordEvent) {
        AuthenticationSource source = wrongPasswordEvent.getSource();
        if (source != AuthenticationSource.LOGIN && source != AuthenticationSource.TOTP)
            return;
        if (plugin.getConfiguration().get(ConfigurationKeys.MAX_LOGIN_ATTEMPTS) == -1)
            return;

        P player = wrongPasswordEvent.getPlayer();
        if (player == null) return;

        var key = trackingKeyFor(player, wrongPasswordEvent.getUser());
        if (key == null) return;

        // if key do not exists, put 1 as value
        // otherwise sum 1 to the value linked to key
        int currentLoginTry = loginTries.asMap().merge(key, 1, Integer::sum);
        if (currentLoginTry >= plugin.getConfiguration().get(ConfigurationKeys.MAX_LOGIN_ATTEMPTS)) {
            var kickMessage = banEnabled()
                    ? plugin.getMessages().getMessage("kick-banned-brute-force", "%seconds%", String.valueOf(banSeconds))
                    : plugin.getMessages().getMessage(source == AuthenticationSource.LOGIN ? "kick-error-password-wrong" : "kick-error-totp-wrong");

            if (banEnabled()) {
                bans.put(key, System.currentTimeMillis() + (banSeconds * 1000L));
                // The ban supersedes the attempt counter; leaving it at the limit would ban the
                // player again on their first wrong password after the ban expires.
                loginTries.invalidate(key);
            }

            plugin.getPlatformHandle().kick(player, kickMessage);
        }
    }

    private void onAuthenticated(AuthenticatedEvent<P, S> authenticatedEvent) {
        P player = authenticatedEvent.getPlayer();
        if (player == null) return;

        var key = trackingKeyFor(player, authenticatedEvent.getUser());
        if (key != null) loginTries.invalidate(key);
    }

    /**
     * @return the tracking key for a connected player, or null if it cannot be determined
     */
    private String trackingKeyFor(P player, User user) {
        if (banByIP) return plugin.getPlatformHandle().getIP(player);

        // Floodgate players have no database profile; they cannot be tracked by name.
        return user == null ? null : trackingKey(null, user.getLastNickname());
    }

}
