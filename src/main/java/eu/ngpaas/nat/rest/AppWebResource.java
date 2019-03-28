/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.ngpaas.nat.rest;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import eu.ngpaas.nat.core.NATManager;
import eu.ngpaas.pmlib.PolicyHelper;
import eu.ngpaas.pmlib.PolicyRule;
import eu.ngpaas.pmlib.PolicyService;
import eu.ngpaas.pmlib.SimpleResponse;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Sample web resource.
 */
@Path("")
public class AppWebResource extends AbstractWebResource {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private PolicyService natService = new NATManager();

    @POST
    @Path("formalvalidation")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response formalvalidation(String body) {
        PolicyRule policyRule = PolicyHelper.parsePolicyRule(body);
        SimpleResponse sr = natService.formalValidation(policyRule);
        return ok(sr.getMessage()).
                                      status(sr.getCode()).
                                      build();
    }

    @POST
    @Path("contextvalidation")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response contextvalidation(String body) {
        PolicyRule policyRule = PolicyHelper.parsePolicyRule(body);
        SimpleResponse sr = natService.contextValidation(policyRule);
        return ok(sr.getMessage()).
                                      status(sr.getCode()).
                                      build();
    }

    @POST
    @Path("enforce")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response enforce(String body) {
        PolicyRule policyRule = PolicyHelper.parsePolicyRule(body);
        natService.enforce(policyRule);
        return Response.status(Response.Status.OK).build();
    }

    @POST
    @Path("remove")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response remove(String body) {
        PolicyRule policyRule = PolicyHelper.parsePolicyRule(body);
        natService.remove(policyRule);
        return Response.status(Response.Status.OK).build();
    }

}
