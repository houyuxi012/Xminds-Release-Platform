import {
  ApartmentOutlined,
  AuditOutlined,
  BellOutlined,
  CloudServerOutlined,
  CodeOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  QuestionCircleOutlined,
  RocketOutlined,
} from '@ant-design/icons';
import { ProLayout } from '@ant-design/pro-components';
import { Badge, Select, Space, Tag, Typography } from 'antd';
import type { ReactNode } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import type { PlatformRole } from '../api/types';
import { platformRoleLabels, useAuth } from '../auth/AuthProvider';

const menuRoutes = [
  { path: '/', name: '概览', icon: <ApartmentOutlined /> },
  {
    path: '/release-management',
    name: '发布管理',
    routes: [
      { path: '/products', name: '产品', icon: <DatabaseOutlined /> },
      { path: '/artifacts', name: '制品', icon: <CloudServerOutlined /> },
      { path: '/releases', name: 'Release', icon: <RocketOutlined /> },
    ],
  },
  {
    path: '/integration',
    name: '集成与分发',
    routes: [
      { path: '/scm', name: 'SCM 连接', icon: <CodeOutlined /> },
      { path: '/endpoints', name: '分发端点', icon: <DeploymentUnitOutlined /> },
    ],
  },
  {
    path: '/governance',
    name: '可观测与治理',
    routes: [{ path: '/audit', name: '日志中心', icon: <AuditOutlined /> }],
  },
];

export function AppShell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { activeRole, setActiveRole, principal } = useAuth();

  return (
    <div data-testid="console-shell" data-navigation-surface="white">
      <ProLayout
        title="Xminds Release"
        logo={<span className="brand-mark">X</span>}
        route={{ routes: menuRoutes }}
        location={{ pathname: location.pathname }}
        layout="mix"
        splitMenus={false}
        fixedHeader
        fixSiderbar
        pageTitleRender={() => 'Xminds Release Platform'}
        siderWidth={224}
        collapsedButtonRender={false}
        menu={{ autoClose: false }}
        menuItemRender={(item, dom) => (
          <button
            type="button"
            className="menu-link-button"
            onClick={() => item.path && navigate(item.path)}
          >
            {dom}
          </button>
        )}
        menuHeaderRender={undefined}
        headerTitleRender={(logo, title) => (
          <div className="header-brand">
            {logo}
            {title}
            <Tag color="blue" variant="filled">
              P0
            </Tag>
          </div>
        )}
        actionsRender={() => [
          <Tag key="environment" color="green" variant="filled">
            生产模拟环境
          </Tag>,
          <QuestionCircleOutlined key="help" aria-label="帮助" className="header-icon" />,
          <Badge key="notification" dot>
            <BellOutlined aria-label="通知" className="header-icon" />
          </Badge>,
          <Space key="principal" size={8}>
            <div className="principal-copy">
              <Typography.Text strong>{principal.displayName}</Typography.Text>
              <Typography.Text type="secondary">演示权限</Typography.Text>
            </div>
            <Select<PlatformRole>
              aria-label="演示角色"
              value={activeRole}
              onChange={setActiveRole}
              placement="bottomRight"
              popupMatchSelectWidth={false}
              options={(Object.keys(platformRoleLabels) as PlatformRole[]).map((role) => ({
                value: role,
                label: platformRoleLabels[role],
              }))}
            />
          </Space>,
        ]}
        token={{
          header: { colorBgHeader: '#ffffff', colorHeaderTitle: '#1f1f1f' },
          sider: {
            colorMenuBackground: '#ffffff',
            colorTextMenu: '#344054',
            colorTextMenuSelected: '#1677ff',
            colorBgMenuItemSelected: '#e6f4ff',
          },
          pageContainer: { paddingInlinePageContainerContent: 24 },
        }}
      >
        <main className="console-content">{children}</main>
      </ProLayout>
    </div>
  );
}
