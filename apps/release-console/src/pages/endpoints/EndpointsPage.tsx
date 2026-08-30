import { ReloadOutlined } from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import { Alert, App as AntApp, Button, Descriptions, Space, Timeline, Typography } from 'antd';
import { useState } from 'react';
import { endpoints } from '../../api/demoData';
import type { DistributionEndpoint } from '../../api/types';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

export function EndpointsPage() {
  const { message } = AntApp.useApp();
  const [selected, setSelected] = useState<DistributionEndpoint | null>(null);

  const columns: ProColumns<DistributionEndpoint>[] = [
    { title: '优先级', dataIndex: 'priority', width: 80, search: false },
    {
      title: '端点',
      dataIndex: 'name',
      render: (_, record) => (
        <div className="table-primary-cell">
          <Typography.Text strong>{record.name}</Typography.Text>
          <span>{record.kind}</span>
        </div>
      ),
    },
    { title: '区域', dataIndex: 'region', valueType: 'select' },
    {
      title: 'Root 摘要',
      dataIndex: 'rootDigest',
      search: false,
      render: (value) => <span className="mono">{String(value)}</span>,
    },
    {
      title: 'Timestamp 摘要',
      dataIndex: 'timestampDigest',
      search: false,
      render: (value) => <span className="mono">{String(value)}</span>,
    },
    {
      title: '健康状态',
      dataIndex: 'health',
      valueType: 'select',
      render: (_, record) => <StatusTag status={record.health} />,
    },
    { title: '最近检查', dataIndex: 'checkedAt', search: false },
    {
      title: '操作',
      valueType: 'option',
      render: (_, record) => [
        <Button key="detail" type="link" onClick={() => setSelected(record)}>
          查看详情
        </Button>,
      ],
    },
  ];

  return (
    <PageContainer
      title="分发端点"
      content="验证可信目录与引用制品的目标端摘要，连续失败的端点会自动退出健康集合。"
    >
      <ProTable<DistributionEndpoint>
        rowKey="id"
        columns={columns}
        dataSource={endpoints}
        search={{ labelWidth: 'auto' }}
        options={{ density: true, setting: true, reload: true }}
      />
      <WhiteDetailDrawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.name || '端点详情'}
        footer={
          selected?.health === 'degraded' ? (
            <Button
              type="primary"
              icon={<ReloadOutlined />}
              onClick={() => message.success('已创建受控同步重试任务')}
            >
              重试同步
            </Button>
          ) : null
        }
      >
        {selected ? (
          <Space orientation="vertical" size={24} style={{ width: '100%' }}>
            {selected.health === 'degraded' ? (
              <Alert
                type="warning"
                showIcon
                title="Timestamp 摘要未收敛"
                description="连续失败 2 次；达到 3 次后端点将自动退出健康集合。"
              />
            ) : null}
            <Descriptions bordered size="small" column={2} title="端点摘要">
              <Descriptions.Item label="类型">{selected.kind}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag status={selected.health} />
              </Descriptions.Item>
              <Descriptions.Item label="区域">{selected.region}</Descriptions.Item>
              <Descriptions.Item label="优先级">{selected.priority}</Descriptions.Item>
              <Descriptions.Item label="Root" span={2}>
                <span className="mono">{selected.rootDigest}</span>
              </Descriptions.Item>
              <Descriptions.Item label="Timestamp" span={2}>
                <span className="mono">{selected.timestampDigest}</span>
              </Descriptions.Item>
            </Descriptions>
            <Timeline
              items={[
                {
                  color: 'green',
                  content: (
                    <>
                      <strong>复制五角色目录</strong>
                      <div className="timeline-code">
                        root · targets · snapshot · timestamp · revocation
                      </div>
                    </>
                  ),
                },
                {
                  color: 'green',
                  content: (
                    <>
                      <strong>复制引用制品</strong>
                      <div className="timeline-code">2 个内容寻址对象</div>
                    </>
                  ),
                },
                {
                  color: selected.health === 'degraded' ? 'red' : 'green',
                  content: (
                    <>
                      <strong>目标端摘要回读</strong>
                      <div className="timeline-code">{selected.checkedAt}</div>
                    </>
                  ),
                },
              ]}
            />
          </Space>
        ) : null}
      </WhiteDetailDrawer>
    </PageContainer>
  );
}
