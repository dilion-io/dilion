/**
 * Minimal ambient types for `swagger-ui-dist`.
 *
 * The package ships a UMD bundle and no `.d.ts`, and `@types/swagger-ui` only
 * covers the React component, not the bundle entry. Rather than pull a whole
 * typings package for one call site, this declares exactly the surface
 * `src/pages/DocsPage.tsx` uses. Everything opaque is `unknown`, so no `any`
 * escapes into app code.
 */
declare module 'swagger-ui-dist/swagger-ui-bundle.js' {
  /** The mutable request object handed to `requestInterceptor`. */
  export interface SwaggerRequest {
    url: string
    method?: string
    headers?: Record<string, string>
    body?: unknown
    credentials?: RequestCredentials
    [extra: string]: unknown
  }

  /** The subset of SwaggerUI's config this app sets. */
  export interface SwaggerUIConfig {
    domNode: Element
    url?: string
    spec?: unknown
    presets?: readonly unknown[]
    plugins?: readonly unknown[]
    layout?: string
    deepLinking?: boolean
    docExpansion?: 'list' | 'full' | 'none'
    defaultModelsExpandDepth?: number
    tryItOutEnabled?: boolean
    persistAuthorization?: boolean
    withCredentials?: boolean
    supportedSubmitMethods?: readonly string[]
    requestInterceptor?: (request: SwaggerRequest) => SwaggerRequest | Promise<SwaggerRequest>
    onComplete?: () => void
  }

  /** Opaque handle; nothing in this app reaches into it. */
  export type SwaggerUIInstance = Record<string, unknown>

  interface SwaggerUIBundleStatic {
    (config: SwaggerUIConfig): SwaggerUIInstance
    readonly presets: { readonly apis: unknown }
    readonly plugins: Readonly<Record<string, unknown>>
  }

  const SwaggerUIBundle: SwaggerUIBundleStatic
  export default SwaggerUIBundle
}
