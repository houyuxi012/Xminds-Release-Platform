import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App as AntApp, ConfigProvider } from 'antd';
import { useState } from 'react';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import { AuthProvider } from '../auth/AuthProvider';
import { ConsoleRoutes } from './routes';
import { consoleTheme } from './theme';
import '../styles.css';

export interface AppProps {
  initialEntries?: string[];
  initialRoles?: string[];
}

export function App({ initialEntries, initialRoles }: AppProps) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { retry: false, staleTime: 30_000 },
          mutations: { retry: false },
        },
      }),
  );
  const Router = initialEntries ? MemoryRouter : BrowserRouter;
  const routerProps = initialEntries ? { initialEntries } : {};

  return (
    <ConfigProvider theme={consoleTheme}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <AuthProvider initialRoles={initialRoles}>
            <Router {...routerProps}>
              <ConsoleRoutes />
            </Router>
          </AuthProvider>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>
  );
}
