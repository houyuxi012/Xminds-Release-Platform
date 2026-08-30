import { Drawer, type DrawerProps } from 'antd';
import type { ReactNode } from 'react';

export interface WhiteDetailDrawerProps extends Omit<DrawerProps, 'children'> {
  children: ReactNode;
}

export function WhiteDetailDrawer({ children, size = 800, ...props }: WhiteDetailDrawerProps) {
  return (
    <Drawer
      {...props}
      size={size}
      rootClassName="white-detail-drawer"
      data-testid="white-detail-drawer"
      styles={{
        header: { background: '#ffffff' },
        body: { background: '#ffffff' },
        footer: { background: '#ffffff' },
      }}
    >
      {children}
    </Drawer>
  );
}
