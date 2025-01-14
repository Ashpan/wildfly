/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
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

package org.jboss.as.ejb3.subsystem;

import static org.jboss.as.ejb3.logging.EjbLogger.ROOT_LOGGER;

import java.util.Timer;

import org.jboss.as.controller.AbstractBoottimeAddStepHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.ejb3.deployment.processors.AroundTimeoutAnnotationParsingProcessor;
import org.jboss.as.ejb3.deployment.processors.TimerServiceDeploymentProcessor;
import org.jboss.as.ejb3.deployment.processors.annotation.TimerServiceAnnotationProcessor;
import org.jboss.as.ejb3.deployment.processors.merging.TimerMethodMergingProcessor;
import org.jboss.as.ejb3.timerservice.TimerServiceMetaData;
import org.jboss.as.server.AbstractDeploymentChainStep;
import org.jboss.as.server.DeploymentProcessorTarget;
import org.jboss.as.server.deployment.Phase;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;

/**
 * Adds the timer service
 *
 * @author Stuart Douglas
 */
public class TimerServiceAdd extends AbstractBoottimeAddStepHandler {

    public static final TimerServiceAdd INSTANCE = new TimerServiceAdd();

    private TimerServiceAdd() {
        super(TimerServiceResourceDefinition.ATTRIBUTES);
    }

    @Override
    protected void performBoottime(final OperationContext context, ModelNode operation, final ModelNode model) throws OperationFailedException {

        final String threadPoolName = TimerServiceResourceDefinition.THREAD_POOL_NAME.resolveModelAttribute(context, model).asStringOrNull();

        TimerServiceMetaData defaultMetaData = new TimerServiceMetaData();
        defaultMetaData.setDataStoreName(TimerServiceResourceDefinition.DEFAULT_DATA_STORE.resolveModelAttribute(context, model).asStringOrNull());
        defaultMetaData.setPersistentTimerManagementProvider(TimerServiceResourceDefinition.DEFAULT_PERSISTENT_TIMER_MANAGEMENT.resolveModelAttribute(context, model).asStringOrNull());
        defaultMetaData.setTransientTimerManagementProvider(TimerServiceResourceDefinition.DEFAULT_TRANSIENT_TIMER_MANAGEMENT.resolveModelAttribute(context, model).asStringOrNull());

        context.addStep(new AbstractDeploymentChainStep() {
            @Override
            protected void execute(DeploymentProcessorTarget processorTarget) {
                ROOT_LOGGER.debug("Configuring timers");
                //we only add the timer service DUP's when the timer service in enabled in XML
                processorTarget.addDeploymentProcessor(EJB3Extension.SUBSYSTEM_NAME, Phase.PARSE, Phase.PARSE_TIMEOUT_ANNOTATION, new TimerServiceAnnotationProcessor());
                processorTarget.addDeploymentProcessor(EJB3Extension.SUBSYSTEM_NAME, Phase.PARSE, Phase.PARSE_AROUNDTIMEOUT_ANNOTATION, new AroundTimeoutAnnotationParsingProcessor());
                processorTarget.addDeploymentProcessor(EJB3Extension.SUBSYSTEM_NAME, Phase.POST_MODULE, Phase.POST_MODULE_EJB_TIMER_METADATA_MERGE, new TimerMethodMergingProcessor());
                processorTarget.addDeploymentProcessor(EJB3Extension.SUBSYSTEM_NAME, Phase.POST_MODULE, Phase.POST_MODULE_EJB_TIMER_SERVICE, new TimerServiceDeploymentProcessor(threadPoolName, defaultMetaData));
            }
        }, OperationContext.Stage.RUNTIME);

        if (threadPoolName != null) {
            context.getCapabilityServiceTarget().addCapability(TimerServiceResourceDefinition.TIMER_SERVICE_CAPABILITY, new TimerValueService()).install();
        }
    }

    private static final class TimerValueService implements Service<Timer> {

        private Timer timer;

        @Override
        public synchronized void start(final StartContext context) throws StartException {
            timer = new Timer();
        }

        @Override
        public synchronized void stop(final StopContext context) {
            timer.cancel();
            timer = null;
        }

        @Override
        public synchronized Timer getValue() throws IllegalStateException, IllegalArgumentException {
            return timer;
        }
    }
}
