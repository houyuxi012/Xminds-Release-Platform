import { CopyOutlined, PlusOutlined } from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import { useQuery } from '@tanstack/react-query';
import { Alert, App as AntApp, Button, Descriptions, Space, Tag, Typography } from 'antd';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiContractError, ApiProblemError, apiClient } from '../../api/client';
import type { Product } from '../../api/types';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

export function ProductsPage() {
  const navigate = useNavigate();
  const { message } = AntApp.useApp();
  const [selected, setSelected] = useState<Product | null>(null);
  const productsQuery = useQuery({
    queryKey: ['products', { limit: 50 }],
    queryFn: () => apiClient.listProducts({ limit: 50 }),
  });

  const errorTitle = (() => {
    if (productsQuery.error instanceof ApiProblemError) {
      const { title, code } = productsQuery.error.problem;
      return `${title}${code ? `（${code}）` : ''}`;
    }
    if (productsQuery.error instanceof ApiContractError) {
      return 'API 响应不符合契约';
    }
    return '无法加载产品';
  })();

  const errorDetail = (() => {
    if (productsQuery.error instanceof ApiProblemError) {
      return productsQuery.error.problem.detail || '请稍后重试。';
    }
    if (productsQuery.error instanceof Error) {
      return productsQuery.error.message;
    }
    return '无法连接管理 API，请检查网络或稍后重试。';
  })();

  const columns: ProColumns<Product>[] = [
    {
      title: '产品',
      dataIndex: 'displayName',
      render: (_, record) => (
        <div className="table-primary-cell">
          <Typography.Text strong>{record.displayName}</Typography.Text>
          <span className="mono">{record.id}</span>
        </div>
      ),
    },
    {
      title: '默认通道',
      dataIndex: 'defaultChannel',
      valueType: 'select',
      valueEnum: { stable: 'stable' },
    },
    {
      title: '通道',
      dataIndex: 'channels',
      search: false,
      render: (_, record) => record.channels.map((channel) => channel.name).join('、') || '—',
    },
    {
      title: 'Manifest 摘要',
      dataIndex: 'manifestDigest',
      search: false,
      render: (value) => <Typography.Text className="mono">{String(value)}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      valueType: 'select',
      valueEnum: { active: '已启用', inactive: '已停用' },
      render: (_, record) => <StatusTag status={record.status} />,
    },
    { title: '更新时间', dataIndex: 'updatedAt', search: false },
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
      title="产品"
      content="统一注册产品 Manifest、默认通道与发布范围，不在业务代码中硬编码产品特例。"
    >
      {productsQuery.isError ? (
        <Alert
          type="error"
          showIcon
          title={errorTitle}
          description={
            <Space orientation="vertical" size={2}>
              <span>{errorDetail}</span>
              {productsQuery.error instanceof ApiProblemError &&
              productsQuery.error.problem.request_id ? (
                <strong className="mono">请求 ID：{productsQuery.error.problem.request_id}</strong>
              ) : null}
            </Space>
          }
          action={
            <Button size="small" onClick={() => void productsQuery.refetch()}>
              重试
            </Button>
          }
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <ProTable<Product>
        rowKey="id"
        columns={columns}
        dataSource={productsQuery.data?.items ?? []}
        loading={productsQuery.isPending || productsQuery.isFetching}
        options={{
          density: true,
          setting: true,
          reload: () => void productsQuery.refetch(),
        }}
        search={false}
        pagination={{ pageSize: 10, showSizeChanger: false }}
        toolBarRender={() => [
          <Button
            key="create"
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => navigate('/products/new')}
          >
            创建产品
          </Button>,
        ]}
      />

      <WhiteDetailDrawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.displayName} · 产品详情` : '产品详情'}
      >
        {selected ? (
          <Descriptions title="基本信息" column={2} bordered size="small">
            <Descriptions.Item label="产品标识">
              <Space>
                <span className="mono">{selected.id}</span>
                <Button
                  type="text"
                  size="small"
                  aria-label="复制产品标识"
                  icon={<CopyOutlined />}
                  onClick={() => message.success('产品标识已复制')}
                />
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <StatusTag status={selected.status} />
            </Descriptions.Item>
            <Descriptions.Item label="默认通道">{selected.defaultChannel}</Descriptions.Item>
            <Descriptions.Item label="全部通道">
              <Space size={[4, 4]} wrap>
                {selected.channels.map((channel) => (
                  <Tag key={channel.name}>{channel.displayName}</Tag>
                ))}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="Manifest 版本">
              <span className="mono">{selected.schemaVersion}</span>
            </Descriptions.Item>
            <Descriptions.Item label="版本规则">{selected.versionScheme}</Descriptions.Item>
            <Descriptions.Item label="制品类型" span={2}>
              <Space size={[4, 4]} wrap>
                {selected.artifactTypes.map((artifactType) => (
                  <Tag key={artifactType} color="blue">
                    {artifactType}
                  </Tag>
                ))}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="兼容性键" span={2}>
              {selected.compatibilityKeys.length > 0 ? (
                <Space size={[4, 4]} wrap>
                  {selected.compatibilityKeys.map((key) => (
                    <Tag key={key}>{key}</Tag>
                  ))}
                </Space>
              ) : (
                '—'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="Manifest 摘要" span={2}>
              <span className="mono">{selected.manifestDigest}</span>
            </Descriptions.Item>
            <Descriptions.Item label="目录格式">
              <span className="mono">{selected.catalogFormat}</span>
            </Descriptions.Item>
            <Descriptions.Item label="创建者">
              <span className="mono">{selected.createdBy}</span>
            </Descriptions.Item>
            <Descriptions.Item label="创建时间">{selected.createdAt}</Descriptions.Item>
            <Descriptions.Item label="更新时间">{selected.updatedAt}</Descriptions.Item>
          </Descriptions>
        ) : null}
      </WhiteDetailDrawer>
    </PageContainer>
  );
}
