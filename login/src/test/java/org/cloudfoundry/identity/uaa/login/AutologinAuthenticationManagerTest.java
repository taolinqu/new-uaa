package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.error.InvalidCodeException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class AutologinAuthenticationManagerTest {

    private AutologinAuthenticationManager manager;
    private ExpiringCodeStore codeStore;
    private Authentication authenticationToken;

    @Before
    public void setUp() {
        manager = new AutologinAuthenticationManager();
        codeStore = Mockito.mock(ExpiringCodeStore.class);

        manager.setExpiringCodeStore(codeStore);
        Map<String,String> info = new HashMap<>();
        info.put("code", "the_secret_code");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest(), "test-client-id");
        authenticationToken = new AuthzAuthenticationRequest(info, details);
    }

    @Test
    public void authentication_successful() throws Exception {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "test-user-id");
        codeData.put("client_id", "test-client-id");
        codeData.put("username", "test-username");
        codeData.put(Origin.ORIGIN, Origin.UAA);
        codeData.put("action", ExpiringCodeType.AUTOLOGIN.name());
        when(codeStore.retrieveCode("the_secret_code")).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData)));



        Authentication authenticate = manager.authenticate(authenticationToken);
        assertThat(authenticate, is(instanceOf(UaaAuthentication.class)));
        assertThat(((UaaAuthentication)authenticate).getPrincipal().getId(), is("test-user-id"));
        assertThat(((UaaAuthentication)authenticate).getPrincipal().getName(), is("test-username"));
        assertThat(((UaaAuthentication)authenticate).getPrincipal().getOrigin(), is(Origin.UAA));
    }

    @Test(expected = InvalidCodeException.class)
    public void authentication_fails_withExpiredCode() {
        when(codeStore.retrieveCode("the_secret_code")).thenReturn(null);
        manager.authenticate(authenticationToken);
    }

    @Test(expected = InvalidCodeException.class)
    public void authentication_fails_withCodeIntendedForDifferentPurpose() {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "test-user-id");
        codeData.put("client_id", "test-client-id");
        codeData.put("username", "test-username");
        codeData.put(Origin.ORIGIN, Origin.UAA);

        when(codeStore.retrieveCode("the_secret_code")).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData)));
        manager.authenticate(authenticationToken);
    }

    @Test(expected = InvalidCodeException.class)
    public void authentication_fails_withInvalidCode() {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("action", "someotheraction");

        when(codeStore.retrieveCode("the_secret_code")).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData)));
        manager.authenticate(authenticationToken);
    }


}