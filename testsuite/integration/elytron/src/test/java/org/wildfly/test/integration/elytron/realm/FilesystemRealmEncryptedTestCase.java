/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.test.integration.elytron.realm;

import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import java.net.MalformedURLException;
import java.net.URL;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.as.test.shared.ServerReload;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Full authentication tests for Elytron Encrypted Filesystem Realm.
 *
 * @author Ashpan Raskar <araskar@redhat.com>
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({FilesystemRealmEncryptedTestCase.SetUpTask.class})
public class FilesystemRealmEncryptedTestCase {

    private static final String DEPLOYMENT_ENCRYPTED = "filesystemRealmEncrypted";
    private static final String USER = "plainUser";
    private static final String PASSWORD = "secretPassword";


    @Deployment(name = DEPLOYMENT_ENCRYPTED)
    public static WebArchive deploymentWithCharsetAndEncoded() {
        final WebArchive war = ShrinkWrap.create(WebArchive.class, DEPLOYMENT_ENCRYPTED + ".war");
        war.addClasses(SimpleServlet.class);
        war.addClasses(SimpleSecuredServlet.class);
        war.addAsWebInfResource(FilesystemRealmEncryptedTestCase.class.getPackage(), "filesystem-realm-web.xml", "web.xml");
        war.addAsWebInfResource(Utils.getJBossWebXmlAsset(DEPLOYMENT_ENCRYPTED), "jboss-web.xml");
        return war;
    }

    /**
     *
     * Test Filesystem realm when choosing to encrypt it.
     */
    @Test
    @OperateOnDeployment(DEPLOYMENT_ENCRYPTED)
    public void testEncryption(@ArquillianResource URL webAppURL) throws Exception {
        URL url = prepareURL(webAppURL);
        Utils.makeCallWithBasicAuthn(url, USER, PASSWORD, SC_OK);
    }

    /**
     *
     * Test Filesystem realm when choosing to encrypt it with a bad credential.
     */
    @Test
    @OperateOnDeployment(DEPLOYMENT_ENCRYPTED)
    public void testEncryptionFail(@ArquillianResource URL webAppURL) throws Exception {
        URL url = prepareURL(webAppURL);
        Utils.makeCallWithBasicAuthn(url, USER+"123", PASSWORD, SC_UNAUTHORIZED);
    }


    private URL prepareURL(URL url) throws MalformedURLException {
        return new URL(url.toExternalForm() + SimpleSecuredServlet.SERVLET_PATH.substring(1));
    }

    static class SetUpTask implements ServerSetupTask {

        private static final String REALM_NAME = "fsRealmEncrypted";
        private static final String DOMAIN_NAME = "fsDomainEncrypted";
        private static final String PREDEFINED_HTTP_SERVER_MECHANISM_FACTORY = "global";


        @Override
        public void setup(ManagementClient managementClient, java.lang.String s) throws Exception {
            try (CLIWrapper cli = new CLIWrapper(true)) {
                cli.sendLine("/subsystem=elytron/simple-role-decoder=from-roles-attribute:add(attribute=Roles)");
            }
            setUpTestDomain(DOMAIN_NAME, REALM_NAME, "filesystem", USER, PASSWORD, DEPLOYMENT_ENCRYPTED, "mycredstore", "key");
            ServerReload.reloadIfRequired(managementClient);

        }

        private void setUpTestDomain(String domainName, String realmName, String path, String username, String password, String deployment, String credentialStore, String secretKey) throws Exception {
            try (CLIWrapper cli =  new CLIWrapper(true)) {
                cli.sendLine(String.format("/subsystem=elytron/secret-key-credential-store=%s:add(path=%s.cs, relative-to=jboss.server.config.dir, create=true, populate=true)",
                        credentialStore, credentialStore));
                cli.sendLine(String.format("/subsystem=elytron/filesystem-realm=%s:add(path=%s,relative-to=jboss.server.config.dir, credential-store=%s, secret-key=%s)",
                        realmName, path, credentialStore, secretKey));
                cli.sendLine(String.format("/subsystem=elytron/filesystem-realm=%s:add-identity(identity=%s)", realmName, username));
                cli.sendLine(String.format("/subsystem=elytron/filesystem-realm=%1$s:set-password(identity=%2$s, digest={algorithm=digest-md5, realm=%1$s, password=%3$s})",
                        realmName, username, password));
                cli.sendLine(String.format("/subsystem=elytron/filesystem-realm=%s:add-identity-attribute(identity=%s, name=Roles, value=[JBossAdmin])",
                        realmName, username));
                cli.sendLine(String.format("/subsystem=elytron/security-domain=%1$s:add(realms=[{realm=%2$s,role-decoder=from-roles-attribute}],default-realm=%2$s,permission-mapper=default-permission-mapper)",
                        domainName, realmName));
                cli.sendLine(String.format(
                        "/subsystem=elytron/http-authentication-factory=%1$s:add(http-server-mechanism-factory=%2$s,security-domain=%1$s,"
                                + "mechanism-configurations=[{mechanism-name=BASIC,mechanism-realm-configurations=[{realm-name=\"%1$s\"}]}])",
                        domainName, PREDEFINED_HTTP_SERVER_MECHANISM_FACTORY));
                cli.sendLine(String.format(
                        "/subsystem=undertow/application-security-domain=%s:add(http-authentication-factory=%s)",
                        deployment, domainName));
            }
        }

        @Override
        public void tearDown(ManagementClient managementClient, java.lang.String s) throws Exception {
            tearDownDomain(DEPLOYMENT_ENCRYPTED, DOMAIN_NAME, REALM_NAME, USER, "mycredstore");
            try (CLIWrapper cli = new CLIWrapper(true)) {
                cli.sendLine("/subsystem=elytron/simple-role-decoder=from-roles-attribute:remove()");
            }
            ServerReload.reloadIfRequired(managementClient);

        }

        private void tearDownDomain(String deployment, String domainName, String realmName, String username, String credentialStore) throws Exception {
            try (CLIWrapper cli = new CLIWrapper(true)) {
                cli.sendLine(String.format("/subsystem=undertow/application-security-domain=%s:remove()", deployment));
                cli.sendLine(String.format("/subsystem=elytron/http-authentication-factory=%s:remove()",
                        domainName));
                cli.sendLine(String.format("/subsystem=elytron/security-domain=%s:remove()",
                        domainName));
                cli.sendLine(String.format("/subsystem=elytron/filesystem-realm=%s:remove-identity(identity=%s)", realmName, username));
                cli.sendLine(String.format("/subsystem=elytron/filesystem-realm=%s:remove()", realmName));
                cli.sendLine(String.format("/subsystem=elytron/secret-key-credential-store=%s:remove()",
                        credentialStore));
            }
        }
    }
}
