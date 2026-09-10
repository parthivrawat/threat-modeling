# Example Threat Models

## Web Shop

```python
from threat_modeling import Model, Component, Boundary, DataFlow

app = Model("web-shop")

app.add(Component("browser", component_type="browser"))
app.add(
    Component(
        "web-app",
        name="Web App",
        component_type="service",
        environment="k8s",
        handles=["user-data"],
        exposed=True,
    )
)
app.add(
    Component(
        "payment-gateway",
        name="Payment Gateway",
        component_type="external-service",
        handles=["payment-card", "financial"],
    )
)
app.add(
    Component(
        "database",
        name="Order Database",
        component_type="database",
        stores=["user-data", "pii", "payment-card"],
    )
)
app.add(
    Component(
        "inventory-service",
        name="Inventory Service",
        component_type="service",
        handles=["inventory"],
    )
)
app.add(
    Component(
        "fraud-check",
        name="Third-Party Fraud Check",
        component_type="external-service",
        handles=["pii", "user-data"],
    )
)

app.add(Boundary("internet", untrusted=True, contains=["browser"]))
app.add(
    Boundary(
        "untrusted-external",
        untrusted=True,
        contains=["payment-gateway", "fraud-check"],
    )
)

app.add(
    DataFlow(
        "browse-products",
        "browser",
        "web-app",
        protocol="https",
        auth="session-cookie",
        data_types=["user-data"],
    )
)
app.add(
    DataFlow(
        "checkout",
        "web-app",
        "payment-gateway",
        protocol="https",
        auth="mTLS",
        data_types=["payment-card", "financial"],
    )
)
app.add(
    DataFlow(
        "persist-order",
        "web-app",
        "database",
        protocol="tls",
        auth="sql-auth",
        data_types=["user-data", "pii"],
    )
)
app.add(
    DataFlow(
        "stock-check",
        "web-app",
        "inventory-service",
        protocol="https",
        auth="service-token",
        data_types=["inventory"],
    )
)
app.add(
    DataFlow(
        "fraud-rating",
        "web-app",
        "fraud-check",
        protocol="https",
        auth="api-key",
        data_types=["pii", "user-data"],
    )
)

app.analyze()  # Expect STRIDE findings around the browser, payment gateway, fraud check, and database.
```

## Microservices Mesh

```python
from threat_modeling import Model, Component, Boundary, DataFlow

app = Model("microservices-mesh")

app.add(Component("client", component_type="browser"))
app.add(
    Component(
        "api-gateway",
        name="API Gateway",
        component_type="gateway",
        environment="k8s",
        exposed=True,
    )
)
app.add(
    Component(
        "auth-service",
        name="Auth Service",
        component_type="service",
        handles=["credentials", "token"],
    )
)
app.add(
    Component(
        "order-service",
        name="Order Service",
        component_type="service",
        handles=["user-data", "order"],
    )
)
app.add(
    Component(
        "payment-service",
        name="Payment Service",
        component_type="service",
        handles=["payment-card", "financial"],
    )
)
app.add(
    Component(
        "notification-service",
        name="Notification Service",
        component_type="service",
        handles=["pii"],
    )
)
app.add(
    Component(
        "database",
        name="Service Database",
        component_type="database",
        stores=["user-data", "pii", "order"],
    )
)
app.add(
    Component(
        "message-queue",
        name="Message Queue",
        component_type="queue",
        handles=["order", "pii"],
    )
)

app.add(Boundary("internet", untrusted=True, contains=["client"]))
app.add(
    Boundary(
        "cluster",
        contains=[
            "api-gateway",
            "auth-service",
            "order-service",
            "payment-service",
            "notification-service",
            "database",
            "message-queue",
        ],
    )
)

app.add(
    DataFlow(
        "client-request",
        "client",
        "api-gateway",
        protocol="https",
        auth="bearer",
        data_types=["user-data"],
    )
)
app.add(
    DataFlow(
        "auth-verify",
        "api-gateway",
        "auth-service",
        protocol="https",
        auth="mTLS",
        data_types=["credentials", "token"],
    )
)
app.add(
    DataFlow(
        "place-order",
        "api-gateway",
        "order-service",
        protocol="https",
        auth="jwt",
        data_types=["user-data", "order"],
    )
)
app.add(
    DataFlow(
        "process-payment",
        "order-service",
        "payment-service",
        protocol="https",
        auth="mTLS",
        data_types=["payment-card", "financial"],
    )
)
app.add(
    DataFlow(
        "enqueue-notify",
        "payment-service",
        "message-queue",
        protocol="amqp",
        auth="sasl",
        data_types=["pii"],
    )
)
app.add(
    DataFlow(
        "notify",
        "message-queue",
        "notification-service",
        protocol="amqp",
        auth="sasl",
        data_types=["pii"],
    )
)

app.analyze()  # Expect STRIDE findings around the gateway, payment flow, and queue/notification flows.
```

## CI/CD Pipeline

```python
from threat_modeling import Model, Component, Boundary, DataFlow

app = Model("cicd-pipeline")

app.add(Component("developer", component_type="user"))
app.add(
    Component(
        "scm",
        name="Source Control",
        component_type="source-control",
        stores=["source-code", "credentials"],
    )
)
app.add(
    Component(
        "ci-runner",
        name="CI Runner",
        component_type="service",
        handles=["source-code", "binary", "secret"],
    )
)
app.add(
    Component(
        "artifact-store",
        name="Artifact Store",
        component_type="storage",
        stores=["binary", "secret"],
    )
)
app.add(
    Component(
        "deployment-agent",
        name="Deployment Agent",
        component_type="service",
        handles=["binary"],
    )
)
app.add(
    Component(
        "staging",
        name="Staging Environment",
        component_type="environment",
        handles=["binary"],
    )
)
app.add(
    Component(
        "production",
        name="Production Environment",
        component_type="environment",
        handles=["binary", "secret"],
    )
)

app.add(Boundary("external", untrusted=True, contains=["developer"]))
app.add(Boundary("production-boundary", contains=["production"]))

app.add(
    DataFlow(
        "commit",
        "developer",
        "scm",
        protocol="ssh",
        auth="ssh-key",
        data_types=["source-code"],
    )
)
app.add(
    DataFlow(
        "build-trigger",
        "scm",
        "ci-runner",
        protocol="https",
        auth="webhook-signature",
        data_types=["source-code"],
    )
)
app.add(
    DataFlow(
        "publish-artifact",
        "ci-runner",
        "artifact-store",
        protocol="https",
        auth="signed-token",
        data_types=["binary"],
    )
)
app.add(
    DataFlow(
        "deploy-staging",
        "deployment-agent",
        "staging",
        protocol="ssh",
        auth="mTLS",
        data_types=["binary"],
    )
)
app.add(
    DataFlow(
        "promote-to-prod",
        "staging",
        "production",
        protocol="ssh",
        auth="mTLS",
        data_types=["binary"],
    )
)

app.analyze()  # Expect STRIDE findings around source integrity, artifact tampering, and production promotion.
```

---

These same `Model`, `Component`, `Boundary`, and `DataFlow` patterns translate directly to the Go, Rust, and TypeScript ports. See the API comparison table in [`../API.md`](../API.md) for the equivalent types and calls.
