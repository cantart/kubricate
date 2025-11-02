import { namespaceTemplate, simpleAppTemplate } from '@kubricate/stacks';
import { Stack } from 'kubricate';

import { secretManager } from './setup-secrets';
import { config } from './shared-config';

/**
 * Namespace stack
 */
const namespace = Stack.fromTemplate(namespaceTemplate, {
  name: config.namespace,
});

/**
 * Ingress Controller with TLS Certificate
 *
 * This demonstrates injecting TLS certificate and key as separate
 * environment variables using individual key injection.
 *
 * Note: envFrom cannot be used with TLS secrets because the standard
 * Kubernetes TLS secret keys (tls.crt, tls.key) contain dots, which
 * are invalid characters in environment variable names. This would
 * cause runtime failures in containers.
 */
const ingressControllerApp = Stack.fromTemplate(simpleAppTemplate, {
  namespace: config.namespace,
  imageName: 'nginx',
  name: 'ingress-controller',
})
  .useSecrets(secretManager, c => {
    // Inject certificate from INGRESS_TLS
    c.secrets('INGRESS_TLS').forName('TLS_CERT').inject('env', { key: 'tls.crt' });

    // Inject private key from INGRESS_TLS
    c.secrets('INGRESS_TLS').forName('TLS_KEY').inject('env', { key: 'tls.key' });
  })
  .override({
    service: {
      apiVersion: 'v1',
      kind: 'Service',
      spec: {
        type: 'LoadBalancer',
        ports: [
          {
            port: 443,
            targetPort: 443,
            protocol: 'TCP',
            name: 'https',
          },
        ],
      },
    },
  });

export default {
  namespace,
  ingressControllerApp,
};
