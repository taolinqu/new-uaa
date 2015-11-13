/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.error.InvalidCodeException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.Map;

/**
 * @author Dave Syer
 * 
 */
public class AutologinAuthenticationManager implements AuthenticationManager {

    private Log logger = LogFactory.getLog(getClass());

    private ExpiringCodeStore codeStore;

    public void setExpiringCodeStore(ExpiringCodeStore expiringCodeStore) {
        this.codeStore= expiringCodeStore;
    }

    public ExpiringCode doRetrieveCode(String code) {
        return codeStore.retrieveCode(code);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!(authentication instanceof AuthzAuthenticationRequest)) {
            return null;
        }

        AuthzAuthenticationRequest request = (AuthzAuthenticationRequest) authentication;
        Map<String, String> info = request.getInfo();
        String code = info.get("code");

        ExpiringCode expiringCode = doRetrieveCode(code);
        Map<String,String> codeData = null;
        try {
            if (expiringCode == null) {
                logger.debug("Autologin code has expired");
                throw new InvalidCodeException("expired_code", "Expired code", 422);
            }
            codeData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
            if(codeData.get("action") == null || !codeData.get("action").equals(ExpiringCodeType.AUTOLOGIN.name())) {
                logger.debug("Code is not meant for autologin");
                throw new InvalidCodeException("invalid_code", "Not an autologin code", 422);
            }
        } catch (JsonUtils.JsonUtilException x) {
            throw new BadCredentialsException("JsonConversion error", x);
        }

        String origin;
        String userId;
        String username;
        username = codeData.get("username");
        origin = codeData.get(Origin.ORIGIN);
        userId = codeData.get("user_id");
        UaaPrincipal principal = new UaaPrincipal(userId,username,null,origin,null, IdentityZoneHolder.get().getId());

        return new UaaAuthentication(
                principal,
                UaaAuthority.USER_AUTHORITIES,
                (UaaAuthenticationDetails) authentication.getDetails());
    }
}
