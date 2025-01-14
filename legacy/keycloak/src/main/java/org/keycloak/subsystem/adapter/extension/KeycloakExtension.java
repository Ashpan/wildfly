/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.subsystem.adapter.extension;

import org.jboss.as.controller.ExtensionContext;
import org.jboss.as.controller.ModelVersion;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SubsystemRegistration;
import org.jboss.as.controller.descriptions.ResourceDescriptionResolver;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.extension.AbstractLegacyExtension;
import org.jboss.as.controller.parsing.ExtensionParsingContext;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.keycloak.subsystem.adapter.logging.KeycloakLogger;

import java.util.Collections;
import java.util.Set;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;


/**
 * Main Extension class for the subsystem.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
 */
public final class KeycloakExtension extends AbstractLegacyExtension {

    public static final String SUBSYSTEM_NAME = "keycloak";
    public static final String NAMESPACE_1_1 = "urn:jboss:domain:keycloak:1.1";
    public static final String NAMESPACE_1_2 = "urn:jboss:domain:keycloak:1.2";
    public static final String CURRENT_NAMESPACE = NAMESPACE_1_2;
    private static final KeycloakSubsystemParser PARSER = new KeycloakSubsystemParser();
    static final PathElement PATH_SUBSYSTEM = PathElement.pathElement(SUBSYSTEM, SUBSYSTEM_NAME);
    private static final String RESOURCE_NAME = KeycloakExtension.class.getPackage().getName() + ".LocalDescriptions";
    private static final ModelVersion MGMT_API_VERSION = ModelVersion.create(1,1,0);
    static final PathElement SUBSYSTEM_PATH = PathElement.pathElement(SUBSYSTEM, SUBSYSTEM_NAME);
    private static final ResourceDefinition KEYCLOAK_SUBSYSTEM_RESOURCE = new KeycloakSubsystemDefinition();
    static final RealmDefinition REALM_DEFINITION = new RealmDefinition();
    static final SecureDeploymentDefinition SECURE_DEPLOYMENT_DEFINITION = new SecureDeploymentDefinition();
    static final SecureServerDefinition SECURE_SERVER_DEFINITION = new SecureServerDefinition();
    static final CredentialDefinition CREDENTIAL_DEFINITION = new CredentialDefinition();
    static final RedirecRewritetRuleDefinition REDIRECT_RULE_DEFINITON = new RedirecRewritetRuleDefinition();

    public KeycloakExtension() {
        super("org.keycloak.keycloak-adapter-subsystem", SUBSYSTEM_NAME);
    }

    public static ResourceDescriptionResolver getResourceDescriptionResolver(final String... keyPrefix) {
        StringBuilder prefix = new StringBuilder(SUBSYSTEM_NAME);
        for (String kp : keyPrefix) {
            prefix.append('.').append(kp);
        }
        return new StandardResourceDescriptionResolver(prefix.toString(), RESOURCE_NAME, KeycloakExtension.class.getClassLoader(), true, false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void initializeLegacyParsers(final ExtensionParsingContext context) {
        context.setSubsystemXmlMapping(SUBSYSTEM_NAME, KeycloakExtension.NAMESPACE_1_1, PARSER);
        context.setSubsystemXmlMapping(SUBSYSTEM_NAME, KeycloakExtension.NAMESPACE_1_2, PARSER);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Set<ManagementResourceRegistration> initializeLegacyModel(final ExtensionContext context) {
        KeycloakLogger.ROOT_LOGGER.debug("Activating Keycloak Extension");
        final SubsystemRegistration subsystem = context.registerSubsystem(SUBSYSTEM_NAME, MGMT_API_VERSION);

        ManagementResourceRegistration registration = subsystem.registerSubsystemModel(KEYCLOAK_SUBSYSTEM_RESOURCE);
        registration.registerSubModel(REALM_DEFINITION);
        ManagementResourceRegistration secureDeploymentRegistration = registration.registerSubModel(SECURE_DEPLOYMENT_DEFINITION);
        secureDeploymentRegistration.registerSubModel(CREDENTIAL_DEFINITION);
        secureDeploymentRegistration.registerSubModel(REDIRECT_RULE_DEFINITON);

        ManagementResourceRegistration secureServerRegistration = registration.registerSubModel(SECURE_SERVER_DEFINITION);
        secureServerRegistration.registerSubModel(CREDENTIAL_DEFINITION);
        secureServerRegistration.registerSubModel(REDIRECT_RULE_DEFINITON);

        subsystem.registerXMLElementWriter(PARSER);

        return Collections.singleton(registration);
    }
}
