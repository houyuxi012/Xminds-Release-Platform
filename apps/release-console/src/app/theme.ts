import type { ThemeConfig } from 'antd';

export const consoleTheme: ThemeConfig = {
  cssVar: { prefix: 'xminds' },
  token: {
    colorPrimary: '#1677ff',
    colorInfo: '#1677ff',
    colorSuccess: '#52c41a',
    colorWarning: '#faad14',
    colorError: '#ff4d4f',
    colorBgLayout: '#f5f7fa',
    colorBgContainer: '#ffffff',
    colorText: '#1f1f1f',
    colorTextSecondary: '#667085',
    colorBorderSecondary: '#f0f0f0',
    borderRadius: 6,
    fontSize: 14,
    controlHeight: 32,
    wireframe: false,
  },
  components: {
    Layout: {
      bodyBg: '#f5f7fa',
      headerBg: '#ffffff',
      siderBg: '#ffffff',
    },
    Menu: {
      itemBg: '#ffffff',
      itemSelectedBg: '#e6f4ff',
      itemSelectedColor: '#1677ff',
      itemHoverBg: '#f2f7ff',
      itemBorderRadius: 6,
    },
    Drawer: {
      colorBgElevated: '#ffffff',
    },
    Table: {
      headerBg: '#fafafa',
      rowHoverBg: '#f7fbff',
    },
  },
};
