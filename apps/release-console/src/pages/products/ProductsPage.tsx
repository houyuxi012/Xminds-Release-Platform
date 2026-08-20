import { CopyOutlined, PlusOutlined } from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import { App as AntApp, Button, Descriptions, Space, Typography } from 'antd';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { products } from '../../api/demoData';
import type { Product } from '../../api/types';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

export function ProductsPage() {
  const navigate = useNavigate();
  const { message } = AntApp.useApp();
  const [selected, setSelected] = useState<Product | null>(null);

  const columns: ProColumns<Product>[] = [
    {
      title: '产品',
      dataIndex: 'name',
      render: (_, record) => (
        <div className="table-primary-cell">
          <Typography.Text strong>{record.name}</Typography.Text>
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
      render: (_, record) => record.channels.join('、'),
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
      <ProTable<Product>
        rowKey="id"
        columns={columns}
        dataSource={products}
        options={{ density: true, setting: true, reload: true }}
        search={{ labelWidth: 'auto' }}
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
        title={selected ? `${selected.name} · 产品详情` : '产品详情'}
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
            <Descriptions.Item label="全部通道">{selected.channels.join('、')}</Descriptions.Item>
            <Descriptions.Item label="Manifest 摘要" span={2}>
              <span className="mono">{selected.manifestDigest}</span>
            </Descriptions.Item>
            <Descriptions.Item label="说明" span={2}>
              {selected.description}
            </Descriptions.Item>
          </Descriptions>
        ) : null}
      </WhiteDetailDrawer>
    </PageContainer>
  );
}
