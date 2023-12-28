# Datadog Exporter

<!-- status autogenerated section -->
| Status        |           |
| ------------- |-----------|
| Stability     | [alpha]: logs   |
|               | [beta]: traces, metrics   |
| Distributions | [contrib], [aws], [observiq] |
| Issues        | [![Open issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aopen%20label%3Aexporter%2Fdatadog%20&label=open&color=orange&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aopen+is%3Aissue+label%3Aexporter%2Fdatadog) [![Closed issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aclosed%20label%3Aexporter%2Fdatadog%20&label=closed&color=blue&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aclosed+is%3Aissue+label%3Aexporter%2Fdatadog) |
| [Code Owners](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/CONTRIBUTING.md#becoming-a-code-owner)    | [@mx-psi](https://www.github.com/mx-psi), [@dineshg13](https://www.github.com/dineshg13), [@liustanley](https://www.github.com/liustanley), [@songy23](https://www.github.com/songy23), [@mackjmr](https://www.github.com/mackjmr) |
| Emeritus      | [@gbbr](https://www.github.com/gbbr) |

[alpha]: https://github.com/open-telemetry/opentelemetry-collector#alpha
[beta]: https://github.com/open-telemetry/opentelemetry-collector#beta
[contrib]: https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-contrib
[aws]: https://github.com/aws-observability/aws-otel-collector
[observiq]: https://github.com/observIQ/observiq-otel-collector
<!-- end autogenerated section -->

> Please review the Collector's [security documentation](https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/security-best-practices.md), which contains recommendations on securing sensitive information such as the API key required by this exporter.

Visit the [official documentation](https://docs.datadoghq.com/tracing/trace_collection/open_standards/otel_collector_datadog_exporter/) for usage instructions.

## FAQs

### Why am I getting errors 413 - Request Entity Too Large, how do I fix it?

This error indicates the payload size sent by the Datadog exporter exceeds the size limit (see previous examples https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/16834, https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/17566).

This is usually caused by the pipeline batching too many telemetry data before sending to the Datadog exporter. To fix that, try lowering `send_batch_size` and `send_batch_max_size` in your batchprocessor config. You might want to have a separate batch processor dedicated for datadog exporter if other exporters expect a larger batch size, e.g.
```
processors:
  batch:  # To be used by other exporters
    timeout: 1s
    # Default value for send_batch_size is 8192
  batch/datadog:
    send_batch_max_size: 100
    send_batch_size: 10
    timeout: 10s
...
service:
  pipelines:
    metrics:
      receivers: ...
      processors: [batch/datadog]
      exporters: [datadog]
```

The exact values for `send_batch_size` and `send_batch_max_size` depends on your specific workload. Also note that, Datadog intake has different payload size limits for the 3 signal types:
- Trace intake: 3.2MB
- Log intake: https://docs.datadoghq.com/api/latest/logs/
- Metrics V2 intake: https://docs.datadoghq.com/api/latest/metrics/#submit-metrics

### Fall back to the Zorkian metric client with feature gate

Since [v0.69.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/releases/tag/v0.69.0), the Datadog exporter has switched to use the native metric client `datadog-api-client-go` for metric export instead of Zorkian client by default. While `datadog-api-client-go` fixed several issues that are present in Zorkian client, there is a performance regression with it compared to Zorkian client especially under high metric volume. If you observe memory or throughput issues in the Datadog exporter with `datadog-api-client-go`, you can configure the Datadog exporter to fall back to the Zorkian client by disabling the feature gate `exporter.datadogexporter.metricexportnativeclient`, e.g.
```
otelcol --config=config.yaml --feature-gates=-exporter.datadogexporter.metricexportnativeclient
```
Note that we are currently migrating the Datadog metrics exporter to use the metrics serializer instead. The feature flag `exporter.datadogexporter.metricexportnativeclient` will be deprecated and eventually removed in the future, following the [feature lifecycle](https://github.com/open-telemetry/opentelemetry-collector/tree/main/featuregate#feature-lifecycle).

### Remap OTel’s service.name attribute to service for logs

For Datadog Exporter versions 0.83.0 and later, the `service` field of OTel logs is populated as [OTel semantic convention](https://opentelemetry.io/docs/specs/semconv/resource/#service) `service.name`. However, `service.name` is not one of the default [service attributes](https://docs.datadoghq.com/logs/log_configuration/pipelines/?tab=service#service-attribute) in Datadog’s log preprocessing.

To get the service field correctly populated in your logs, you can specify service.name to be the source of a log’s service by setting a [log service remapper processor](https://docs.datadoghq.com/logs/log_configuration/pipelines/?tab=service#service-attribute).

[beta]:https://github.com/open-telemetry/opentelemetry-collector#beta
[alpha]:https://github.com/open-telemetry/opentelemetry-collector#alpha
[contrib]:https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-contrib
[AWS]:https://aws-otel.github.io/docs/partners/datadog