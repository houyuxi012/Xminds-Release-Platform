import type { ProblemDetails, Product } from './types';

export class ApiProblemError extends Error {
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(problem.detail || problem.title);
    this.name = 'ApiProblemError';
    this.problem = problem;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      accept: 'application/json, application/problem+json',
      'content-type': 'application/json',
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const contentType = response.headers.get('content-type') || '';
    if (
      contentType.includes('application/problem+json') ||
      contentType.includes('application/json')
    ) {
      throw new ApiProblemError((await response.json()) as ProblemDetails);
    }
    throw new ApiProblemError({
      type: 'about:blank',
      title: '请求失败',
      status: response.status,
      request_id: response.headers.get('x-request-id') || undefined,
    });
  }

  return (await response.json()) as T;
}

export interface CreateProductInput {
  id: string;
  name: string;
  description: string;
  default_channel: string;
}

export const apiClient = {
  async createProduct(input: CreateProductInput): Promise<Product> {
    if (import.meta.env.MODE === 'development') {
      return {
        id: input.id,
        name: input.name,
        description: input.description,
        defaultChannel: input.default_channel,
        channels: [input.default_channel],
        status: 'active',
        manifestDigest: 'sha256:9b42…f8a1',
        updatedAt: new Date().toISOString(),
      };
    }
    return request<Product>('/api/v1/products', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },
};
