package com.tngb.poc.usecase.routes;

import com.tngb.poc.usecase.processors.RequestProcessor;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class FileRouter extends RouteBuilder {

    @Override
    public void configure() throws Exception {

        from("{{source-file-path}}")
                .routeId("file-route")
                .log(LoggingLevel.INFO, "Received File :: ${header.CamelFileName} with the Body :: ${body}")
                .setProperty("privateKeyPath",simple("{{source-b-private-key-path}}"))
                .setProperty("privateKeyPassword",simple("{{source-b-private-key-password}}"))
                .process(new RequestProcessor())
                .log(LoggingLevel.INFO, "Process ended for the file :: ${header.CamelFileName}");

    }
}
