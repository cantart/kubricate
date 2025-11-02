import { Base64 } from 'js-base64';
import { z } from 'zod';

import type {
  BaseLogger,
  BaseProvider,
  PreparedEffect,
  ProviderInjection,
  SecretInjectionStrategy,
  SecretValue,
} from '@kubricate/core';

import type { EnvVar } from './kubernetes-types.js';
import { createKubernetesMergeHandler } from './merge-utils.js';
import { parseZodSchema } from './utils.js';

export const tlsSecretSchema = z.object({
  cert: z.string().min(1),
  key: z.string().min(1),
});

export interface TlsSecretProviderConfig {
  /**
   * The name of the secret to use.
   */
  name: string;
  /**
   * The namespace of the secret to use.
   *
   * @default 'default'
   */
  namespace?: string;
}

type SupportedStrategies = 'env';
type SuppoertedEnvKeys = 'tls.crt' | 'tls.key';

/**
 * TlsSecretProvider is a provider that uses Kubernetes TLS secrets.
 * It supports only individual key injection (env) because TLS secret keys
 * (tls.crt, tls.key) contain dots which are invalid in environment variable names.
 *
 * envFrom is NOT supported because it would create invalid environment variables
 * like `tls.crt=<value>` which causes runtime failures in containers.
 *
 * The kubernetes.io/tls Secret type has fixed keys: tls.crt and tls.key.
 *
 * @see https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets
 */
export class TlsSecretProvider
  implements BaseProvider<TlsSecretProviderConfig, SupportedStrategies, SuppoertedEnvKeys>
{
  readonly allowMerge = true;
  readonly secretType = 'Kubernetes.Secret.Tls';

  name: string | undefined;
  logger?: BaseLogger;
  readonly targetKind = 'Deployment';
  readonly supportedStrategies: SupportedStrategies[] = ['env'];
  readonly supportedEnvKeys: SuppoertedEnvKeys[] = ['tls.crt', 'tls.key'];

  constructor(public config: TlsSecretProviderConfig) {}

  getTargetPath(strategy: SecretInjectionStrategy): string {
    if (strategy.kind === 'env') {
      if (strategy.targetPath) {
        return strategy.targetPath;
      }
      const index = strategy.containerIndex ?? 0;
      return `spec.template.spec.containers[${index}].env`;
    }

    throw new Error(
      `[TlsSecretProvider] Unsupported injection strategy: ${strategy.kind}. ` +
        `Only 'env' injection is supported because TLS secret keys (tls.crt, tls.key) ` +
        `contain dots which are invalid in environment variable names.`
    );
  }

  getEffectIdentifier(effect: PreparedEffect): string {
    const meta = effect.value?.metadata ?? {};
    return `${meta.namespace ?? 'default'}/${meta.name}`;
  }

  /**
   * Get injection payload for Kubernetes manifests.
   *
   * Only supports 'env' strategy for individual key injection.
   * envFrom is not supported because TLS secret keys (tls.crt, tls.key) contain dots
   * which are invalid in environment variable names.
   *
   * @param injectes Array of provider injections. Must all use 'env' strategy.
   * @returns Array of environment variables
   *
   * @throws {Error} If an unsupported strategy kind is encountered (e.g., 'envFrom')
   *
   * @example
   * // Valid: env strategy with individual keys
   * const envPayload = provider.getInjectionPayload([
   *   { meta: { strategy: { kind: 'env', key: 'tls.crt' }, targetName: 'TLS_CERT' } },
   *   { meta: { strategy: { kind: 'env', key: 'tls.key' }, targetName: 'TLS_KEY' } }
   * ]);
   */
  getInjectionPayload(injectes: ProviderInjection[]): EnvVar[] {
    if (injectes.length === 0) {
      return [];
    }

    // VALIDATION: Ensure all injections use 'env' strategy
    const firstStrategy = this.extractStrategy(injectes[0]);

    if (firstStrategy.kind !== 'env') {
      throw new Error(
        `[TlsSecretProvider] Only 'env' injection is supported. ` +
          `Attempted to use '${firstStrategy.kind}' which is not allowed because ` +
          `TLS secret keys (tls.crt, tls.key) contain dots which are invalid in environment variable names. ` +
          `Use individual key injection with .forName() instead.`
      );
    }

    return this.getEnvInjectionPayload(injectes);
  }

  private extractStrategy(inject: ProviderInjection): SecretInjectionStrategy {
    // Extract strategy from meta if available
    const strategy = inject.meta?.strategy;
    if (strategy) {
      return strategy;
    }

    // Fallback: infer from path
    const path = inject.path;
    if (path.includes('.envFrom')) {
      return { kind: 'envFrom' };
    }
    return { kind: 'env' };
  }

  private getEnvInjectionPayload(injectes: ProviderInjection[]): EnvVar[] {
    return injectes.map(inject => {
      const name = inject.meta?.targetName ?? inject.meta?.secretName;
      const strategy = this.extractStrategy(inject);

      if (!name) {
        throw new Error('[TlsSecretProvider] Missing targetName (.forName) for env injection.');
      }

      // Extract key from strategy
      const key = strategy.kind === 'env' ? strategy.key : undefined;

      if (!key) {
        throw new Error(`[TlsSecretProvider] 'key' is required for env injection. Must be 'tls.crt' or 'tls.key'.`);
      }

      if (key !== 'tls.crt' && key !== 'tls.key') {
        throw new Error(`[TlsSecretProvider] Invalid key '${key}'. Must be 'tls.crt' or 'tls.key'.`);
      }

      return {
        name,
        valueFrom: {
          secretKeyRef: {
            name: this.config.name,
            key,
          },
        },
      };
    });
  }

  /**
   * Merge provider-level effects into final applyable resources.
   * Used to deduplicate (e.g. K8s secret name + ns).
   */
  mergeSecrets(effects: PreparedEffect[]): PreparedEffect[] {
    const merge = createKubernetesMergeHandler();
    return merge(effects);
  }

  prepare(name: string, value: SecretValue): PreparedEffect[] {
    const parsedValue = parseZodSchema(tlsSecretSchema, value);

    const certEncoded = Base64.encode(parsedValue.cert);
    const keyEncoded = Base64.encode(parsedValue.key);

    return [
      {
        secretName: name,
        providerName: this.name,
        type: 'kubectl',
        value: {
          apiVersion: 'v1',
          kind: 'Secret',
          metadata: {
            name: this.config.name,
            namespace: this.config.namespace ?? 'default',
          },
          type: 'kubernetes.io/tls',
          data: {
            'tls.crt': certEncoded,
            'tls.key': keyEncoded,
          },
        },
      },
    ];
  }
}
