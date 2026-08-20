import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloudSyncOutlined,
  ExclamationCircleOutlined,
  PlusOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { PageContainer, ProCard } from '@ant-design/pro-components';
import { Button, Progress, Space, Statistic, Tag, Typography } from 'antd';
import { useNavigate } from 'react-router-dom';
import { releases } from '../../api/demoData';
import { StatusTag } from '../../components/StatusTag';

const metrics = [
  { title: '待审批', value: 1, suffix: '个', icon: <ClockCircleOutlined />, path: '/releases' },
  { title: '发布中', value: 0, suffix: '个', icon: <CloudSyncOutlined />, path: '/releases' },
  {
    title: '失败任务',
    value: 1,
    suffix: '个',
    icon: <ExclamationCircleOutlined />,
    path: '/releases',
  },
  {
    title: '端点健康度',
    value: 92,
    suffix: '%',
    icon: <CheckCircleOutlined />,
    path: '/endpoints',
  },
];

export function OverviewPage() {
  const navigate = useNavigate();

  return (
    <PageContainer
      title="发布概览"
      content={
        <span className="page-summary">
          聚焦多产品可信发布、职责分离审批、目录签名与分发端点健康状态。
        </span>
      }
      extra={[
        <Button
          key="create"
          type="primary"
          icon={<PlusOutlined />}
          aria-label="创建 Release"
          onClick={() => navigate('/releases')}
        >
          创建 Release
        </Button>,
      ]}
    >
      <div className="metric-grid">
        {metrics.map((metric) => (
          <ProCard
            key={metric.title}
            className="page-card"
            hoverable
            onClick={() => navigate(metric.path)}
          >
            <Space align="start" style={{ width: '100%', justifyContent: 'space-between' }}>
              <Statistic title={metric.title} value={metric.value} suffix={metric.suffix} />
              <span style={{ color: '#1677ff', fontSize: 22 }}>{metric.icon}</span>
            </Space>
            {metric.title === '端点健康度' ? (
              <Progress percent={92} showInfo={false} size="small" status="active" />
            ) : null}
          </ProCard>
        ))}
      </div>

      <div className="content-grid">
        <ProCard
          title="最近 Release"
          className="page-card"
          extra={<Button type="link">查看全部</Button>}
        >
          <ul className="overview-release-list">
            {releases.map((release) => (
              <li key={release.id}>
                <div>
                  <Space>
                    <Typography.Text strong>{release.version}</Typography.Text>
                    <StatusTag status={release.status} />
                  </Space>
                  <div className="overview-release-meta">
                    {release.product} · {release.channel} · {release.updatedAt}
                  </div>
                </div>
                <Button type="link" onClick={() => navigate(`/releases/${release.id}`)}>
                  查看详情
                </Button>
              </li>
            ))}
          </ul>
        </ProCard>

        <ProCard title="风险与提醒" className="page-card">
          <ul className="risk-list">
            <li>
              <WarningOutlined style={{ color: '#faad14', marginTop: 3 }} />
              <div>
                <Typography.Text strong>隔离区端点摘要不一致</Typography.Text>
                <br />
                <Typography.Text type="secondary">已进入第 2 次受控重试</Typography.Text>
              </div>
            </li>
            <li>
              <ClockCircleOutlined style={{ color: '#1677ff', marginTop: 3 }} />
              <div>
                <Typography.Text strong>Release 1.2.3 等待审批</Typography.Text>
                <br />
                <Typography.Text type="secondary">提交者与审批者必须不同</Typography.Text>
              </div>
            </li>
            <li>
              <CheckCircleOutlined style={{ color: '#52c41a', marginTop: 3 }} />
              <div>
                <Typography.Text strong>在线签名材料状态正常</Typography.Text>
                <br />
                <Space size={4}>
                  <Tag variant="filled">targets</Tag>
                  <Tag variant="filled">snapshot</Tag>
                  <Tag variant="filled">timestamp</Tag>
                  <Tag variant="filled">revocation</Tag>
                </Space>
              </div>
            </li>
          </ul>
        </ProCard>
      </div>
    </PageContainer>
  );
}
