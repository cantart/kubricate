# Example: With TLS Secret

This example demonstrates how to use **TlsSecretProvider** to manage `kubernetes.io/tls` secrets for TLS certificates and private keys in your Kubernetes deployments.

## 📖 Overview

This example shows how to inject TLS certificates and private keys as environment variables using **individual key injection** with the `env` strategy.

### ⚠️ Important: envFrom Not Supported

**TlsSecretProvider does NOT support `envFrom` (bulk injection)**. Only individual key injection with `env` is supported.

**Why?** The Kubernetes `kubernetes.io/tls` secret type uses fixed key names `tls.crt` and `tls.key`, which contain **dots**. Dots are **invalid characters in environment variable names**, causing runtime failures when containers attempt to start.

```typescript
// ❌ NOT SUPPORTED - Would create invalid env vars
c.secrets('TLS').inject('envFrom');
// Would result in: tls.crt=<value>, tls.key=<value> (INVALID!)

// ✅ CORRECT - Individual key injection with valid env var names
c.secrets('TLS').forName('TLS_CERT').inject('env', { key: 'tls.crt' });
c.secrets('TLS').forName('TLS_KEY').inject('env', { key: 'tls.key' });
// Results in: TLS_CERT=<value>, TLS_KEY=<value> (valid)
```

### Production Note

While this example demonstrates environment variable injection for educational purposes, **production deployments should mount TLS certificates as volumes** for better security. Volume mounting support is planned for future releases.

## 🏗️ What's Included

### Stacks

- **namespace** - Namespace (`kubricate-with-tls-secret`)
- **ingressControllerApp** - Ingress controller with TLS certificate injected as environment variables

### Features Demonstrated

- ✅ `kubernetes.io/tls` Secret type generation
- ✅ Individual key injection with `.inject('env', { key: 'tls.crt' })`
- ✅ Custom environment variable naming with `.forName()`
- ✅ Type-safe TLS certificate management from `.env` file

## 🚀 Quick Start

### 1. Setup Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` to set your TLS certificate (or use the example values for testing):

```bash
# Ingress TLS Certificate
INGRESS_TLS={"cert":"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----","key":"-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"}
```

**Format requirements:**
- PEM-encoded certificate and private key
- Newlines must be escaped as `\\n` in JSON
- Use the `cert` and `key` fields

### 2. Generate Kubernetes Manifests

```bash
pnpm kbr generate
```

Or from the monorepo root:

```bash
pnpm --filter=@examples/with-tls-secret kubricate generate
```

### 3. Review Generated Resources

```bash
ls -la output/
```

You should see:
- `namespace.yml` - Namespace definition
- `ingressControllerApp.yml` - Deployment and Service with TLS secrets injected

## 📋 How It Works

### Secret Configuration

The TLS secret is configured in `src/setup-secrets.ts`:

```typescript
export const secretManager = new SecretManager()
  .addConnector('EnvConnector', new EnvConnector())
  .addProvider(
    'IngressTlsProvider',
    new TlsSecretProvider({
      name: 'ingress-tls',
      namespace: config.namespace,
    })
  )
  .setDefaultConnector('EnvConnector')
  .setDefaultProvider('IngressTlsProvider')
  .addSecret({
    name: 'INGRESS_TLS',
    provider: 'IngressTlsProvider',
  });
```

### Stack with Secret Injection

The ingress controller stack in `src/stacks.ts` injects the TLS certificate and key:

```typescript
const ingressControllerApp = Stack.fromTemplate(simpleAppTemplate, {
  namespace: config.namespace,
  imageName: 'nginx',
  name: 'ingress-controller',
})
  .useSecrets(secretManager, c => {
    // Inject certificate as TLS_CERT environment variable
    c.secrets('INGRESS_TLS').forName('TLS_CERT').inject('env', { key: 'tls.crt' });

    // Inject private key as TLS_KEY environment variable
    c.secrets('INGRESS_TLS').forName('TLS_KEY').inject('env', { key: 'tls.key' });
  })
  .override({
    service: {
      apiVersion: 'v1',
      kind: 'Service',
      spec: {
        type: 'LoadBalancer',
        ports: [{ port: 443, targetPort: 443, protocol: 'TCP', name: 'https' }],
      },
    },
  });
```

### Generated Kubernetes Resources

**Secret:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ingress-tls
  namespace: kubricate-with-tls-secret
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-certificate>
  tls.key: <base64-encoded-private-key>
```

**Deployment with Environment Variables:**
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: ingress-controller
        env:
        - name: TLS_CERT
          valueFrom:
            secretKeyRef:
              name: ingress-tls
              key: tls.crt
        - name: TLS_KEY
          valueFrom:
            secretKeyRef:
              name: ingress-tls
              key: tls.key
```

Note how the secret keys `tls.crt` and `tls.key` (with dots) are mapped to valid environment variable names `TLS_CERT` and `TLS_KEY` (without dots).

## 🔐 Secret Management

### Input Format

TlsSecretProvider expects JSON with `cert` and `key` fields:

```json
{
  "cert": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----",
  "key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"
}
```

**Requirements:**
- Certificates and keys must be in PEM format
- Newlines must be escaped as `\\n` when stored in `.env`
- The provider automatically base64-encodes values for Kubernetes

### Multiple TLS Secrets

To manage multiple TLS certificates, create separate provider instances:

```typescript
new SecretManager()
  .addProvider('IngressTlsProvider', new TlsSecretProvider({
    name: 'ingress-tls',
    namespace: 'production',
  }))
  .addProvider('ApiTlsProvider', new TlsSecretProvider({
    name: 'api-tls',
    namespace: 'production',
  }))
  .addSecret({ name: 'INGRESS_TLS', provider: 'IngressTlsProvider' })
  .addSecret({ name: 'API_TLS', provider: 'ApiTlsProvider' });
```

**Why separate providers?** Each `TlsSecretProvider` instance creates a single Kubernetes Secret resource. Since the `kubernetes.io/tls` type has a fixed schema (`tls.crt` + `tls.key`), you need one provider per certificate to avoid key collisions.

## 🎯 Use Cases

This pattern is useful for:

- 🔒 **Ingress TLS Termination** - HTTPS certificates for ingress controllers
- 🔐 **mTLS Authentication** - Mutual TLS between services
- 🌐 **API Gateway TLS** - Secure API gateway communication
- 📡 **Service Mesh** - Certificate management for service mesh sidecars
- 🛡️ **Webhook TLS** - Kubernetes admission webhook certificates

## 📚 Key Concepts

### Why Only Individual Key Injection?

TlsSecretProvider restricts injection to the `env` strategy for a critical reason:

**The Problem:**
- Kubernetes `kubernetes.io/tls` secrets must have keys named `tls.crt` and `tls.key`
- These key names contain **dots** (`.`)
- Environment variable names **cannot contain dots** - they're invalid characters
- Using `envFrom` would create env vars like `tls.crt=<value>` which causes **runtime failures**

**The Solution:**
- Use `.forName()` to specify a **valid** env var name (e.g., `TLS_CERT`)
- Use `.inject('env', { key: 'tls.crt' })` to reference the **secret key** with the dot
- This maps `tls.crt` → `TLS_CERT`, avoiding the invalid character

### Individual Key Injection Syntax

```typescript
c.secrets('INGRESS_TLS')
  .forName('TLS_CERT')              // ← Valid env var name (no dots)
  .inject('env', { key: 'tls.crt' }); // ← Secret key (has dots)
```

**Required:**
- ✅ Must use `.forName()` to specify the environment variable name
- ✅ Must provide `key` parameter: `'tls.crt'` or `'tls.key'`

## 🧪 Testing the Example

### 1. Generate Manifests

```bash
pnpm kbr generate
```

### 2. Verify Secret Generation

```bash
cat output/ingressControllerApp.yml | grep -A 6 "kind: Secret"
```

Expected output:
```yaml
kind: Secret
metadata:
  name: ingress-tls
  namespace: kubricate-with-tls-secret
type: kubernetes.io/tls
data:
  tls.crt: ...
  tls.key: ...
```

### 3. Verify Environment Variables

```bash
cat output/ingressControllerApp.yml | grep -A 12 "env:"
```

You should see `TLS_CERT` and `TLS_KEY` (not `tls.crt` and `tls.key`).

## 🔍 Troubleshooting

### Error: Missing targetName

```
Error: [TlsSecretProvider] Missing targetName (.forName) for env injection.
```

**Cause:** Forgot to specify `.forName()` before `.inject()`

**Solution:**
```typescript
// ❌ Wrong
c.secrets('INGRESS_TLS').inject('env', { key: 'tls.crt' });

// ✅ Correct
c.secrets('INGRESS_TLS')
  .forName('TLS_CERT')
  .inject('env', { key: 'tls.crt' });
```

### Error: Invalid key

```
Error: [TlsSecretProvider] Invalid key 'ca.crt'. Must be 'tls.crt' or 'tls.key'.
```

**Cause:** Using a key name other than `tls.crt` or `tls.key`

**Solution:** Only use the two valid TLS secret keys:
```typescript
.inject('env', { key: 'tls.crt' })  // ✅ Valid
.inject('env', { key: 'tls.key' })  // ✅ Valid
.inject('env', { key: 'ca.crt' })   // ❌ Invalid
```

### Error: Missing key parameter

```
Error: [TlsSecretProvider] 'key' is required for env injection.
```

**Cause:** Not providing the `key` parameter to specify which secret key to inject

**Solution:**
```typescript
// ❌ Wrong
.inject('env')

// ✅ Correct
.inject('env', { key: 'tls.crt' })
```

### Error: envFrom not supported

```
Error: [TlsSecretProvider] Only 'env' injection is supported.
Attempted to use 'envFrom' which is not allowed because TLS secret keys
(tls.crt, tls.key) contain dots which are invalid in environment variable names.
```

**Cause:** Attempting to use `envFrom` for bulk injection

**Solution:** Use individual key injection instead:
```typescript
// ❌ Wrong - envFrom not supported
c.secrets('TLS').inject('envFrom');
c.secrets('TLS').inject('envFrom', { prefix: 'TLS_' });

// ✅ Correct - individual key injection
c.secrets('TLS').forName('TLS_CERT').inject('env', { key: 'tls.crt' });
c.secrets('TLS').forName('TLS_KEY').inject('env', { key: 'tls.key' });
```

### Error: Conflict detected

```
Error: [conflict:k8s] Conflict detected: key "tls.crt" already exists in Secret "ingress-tls"
```

**Cause:** Multiple secrets trying to use the same provider instance

**Solution:** Create separate provider instances for each certificate:
```typescript
// ❌ Wrong
.addProvider('TlsProvider', new TlsSecretProvider({ name: 'ingress-tls' }))
.addSecret({ name: 'INGRESS_TLS' })
.addSecret({ name: 'API_TLS' })  // Conflict!

// ✅ Correct
.addProvider('IngressTlsProvider', new TlsSecretProvider({ name: 'ingress-tls' }))
.addProvider('ApiTlsProvider', new TlsSecretProvider({ name: 'api-tls' }))
.addSecret({ name: 'INGRESS_TLS', provider: 'IngressTlsProvider' })
.addSecret({ name: 'API_TLS', provider: 'ApiTlsProvider' })
```

## 📖 Documentation

- [Official Documentation](https://kubricate.thaitype.dev)
- [Secret Management Guide](../../docs/secrets.md)
- [TlsSecretProvider API](../../packages/plugin-kubernetes/README.md)

## 🤝 Related Examples

- [with-basic-auth-secret](../with-basic-auth-secret) - BasicAuth secret management
- [with-custom-type-secret](../with-custom-type-secret) - Custom secret types
- [with-secret-manager](../with-secret-manager) - General secret management
- [with-stack-template](../with-stack-template) - Basic stack creation

## 📝 Notes

- TlsSecretProvider is part of `@kubricate/plugin-kubernetes` package
- Certificates and keys are automatically base64-encoded by Kubernetes
- The `kubernetes.io/tls` secret type is a Kubernetes built-in type with fixed schema
- **envFrom is NOT supported** - only `env` injection works due to dot characters in key names
- **Production recommendation:** Mount TLS certificates as volumes instead of environment variables for better security (volume mounting support coming in future releases)
