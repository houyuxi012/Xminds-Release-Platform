import {
  ApiOutlined,
  CheckCircleOutlined,
  PlusOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import {
  Alert,
  App as AntApp,
  Button,
  Checkbox,
  Descriptions,
  Form,
  Input,
  Select,
  Space,
  Steps,
  Typography,
} from 'antd';
import { useState } from 'react';
import { scmConnections } from '../../api/demoData';
import type { ScmConnection } from '../../api/types';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

export function ScmPage() {
  const { message } = AntApp.useApp();
  const [selected, setSelected] = useState<ScmConnection | null>(null);
  const [editing, setEditing] = useState(false);
  const [probeDone, setProbeDone] = useState(false);
  const [form] = Form.useForm();

  const closeEditor = () => {
    setEditing(false);
    setProbeDone(false);
    form.resetFields();
  };

  const probeConnection = async () => {
    try {
      await form.validateFields();
    } catch {
      return;
    }
    setProbeDone(true);
    message.success('DNS、TLS、认证、API 与 Webhook 探测通过');
  };

  const columns: ProColumns<ScmConnection>[] = [
    {
      title: '连接',
      dataIndex: 'name',
      render: (_, record) => (
        <div className="table-primary-cell">
          <Typography.Text strong>{record.name}</Typography.Text>
          <span>{record.repository}</span>
        </div>
      ),
    },
    { title: 'Provider', dataIndex: 'provider', valueType: 'select' },
    {
      title: 'Base URL',
      dataIndex: 'baseUrl',
      search: false,
      render: (value) => <span className="mono">{String(value)}</span>,
    },
    { title: '网络策略', dataIndex: 'proxyPolicy', search: false },
    { title: '凭据', dataIndex: 'credentialLabel', search: false },
    {
      title: '状态',
      dataIndex: 'status',
      valueType: 'select',
      render: (_, record) => <StatusTag status={record.status} />,
    },
    { title: '最近探测', dataIndex: 'checkedAt', search: false },
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
      title="SCM 连接"
      content="统一接入 GitHub.com、GHES 与 GitLab Self-Managed，固定出站目标并验证企业 CA。"
    >
      <ProTable<ScmConnection>
        rowKey="id"
        columns={columns}
        dataSource={scmConnections}
        search={{ labelWidth: 'auto' }}
        options={{ density: true, setting: true, reload: true }}
        toolBarRender={() => [
          <Button
            key="create"
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setEditing(true)}
          >
            新建连接
          </Button>,
        ]}
      />

      <WhiteDetailDrawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.name || '连接详情'}
      >
        {selected ? (
          <Space orientation="vertical" size={24} style={{ width: '100%' }}>
            <Descriptions bordered size="small" column={2} title="连接配置">
              <Descriptions.Item label="Provider">{selected.provider}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag status={selected.status} />
              </Descriptions.Item>
              <Descriptions.Item label="Base URL" span={2}>
                <span className="mono">{selected.baseUrl}</span>
              </Descriptions.Item>
              <Descriptions.Item label="API URL" span={2}>
                <span className="mono">{selected.apiUrl}</span>
              </Descriptions.Item>
              <Descriptions.Item label="仓库">{selected.repository}</Descriptions.Item>
              <Descriptions.Item label="凭据元数据">{selected.credentialLabel}</Descriptions.Item>
              <Descriptions.Item label="企业 CA 指纹" span={2}>
                <span className="mono">{selected.caFingerprint}</span>
              </Descriptions.Item>
              <Descriptions.Item label="代理策略" span={2}>
                {selected.proxyPolicy}
              </Descriptions.Item>
            </Descriptions>
            <Alert
              type="success"
              showIcon
              title="能力探测通过"
              description="DNS、TLS、认证、提交查询与状态回写能力正常；Webhook 验签策略已启用。"
            />
          </Space>
        ) : null}
      </WhiteDetailDrawer>

      <WhiteDetailDrawer
        open={editing}
        onClose={closeEditor}
        title="新建 SCM 连接"
        footer={
          <Button
            type="primary"
            disabled={!probeDone}
            onClick={async () => {
              try {
                await form.validateFields();
              } catch {
                return;
              }
              message.success('SCM 连接已保存');
              closeEditor();
            }}
          >
            保存连接
          </Button>
        }
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ provider: 'GitHub Enterprise Server', proxy: 'direct' }}
          onValuesChange={() => setProbeDone(false)}
        >
          <Form.Item label="Provider" name="provider" rules={[{ required: true }]}>
            <Select
              options={[
                { label: 'GitHub.com', value: 'GitHub' },
                { label: 'GitHub Enterprise Server', value: 'GitHub Enterprise Server' },
                { label: 'GitLab Self-Managed', value: 'GitLab Self-Managed' },
              ]}
            />
          </Form.Item>
          <Form.Item label="私有 Base URL" name="baseUrl" rules={[{ required: true }]}>
            <Input placeholder="https://git.corp.example" prefix={<ApiOutlined />} />
          </Form.Item>
          <Form.Item label="API URL" name="apiUrl" rules={[{ required: true }]}>
            <Input placeholder="https://git.corp.example/api/v3" />
          </Form.Item>
          <Form.Item label="仓库" name="repository" rules={[{ required: true }]}>
            <Input placeholder="platform/ngep" />
          </Form.Item>
          <Form.Item label="代理策略" name="proxy">
            <Select
              options={[
                { label: '直连并禁止环境代理', value: 'direct' },
                { label: '使用受控企业代理', value: 'controlled' },
              ]}
            />
          </Form.Item>
          <Form.Item label="凭据名称" name="credentialLabel">
            <Input placeholder="仅记录凭据元数据，不显示秘密" />
          </Form.Item>
          <Form.Item label="企业 CA 指纹" name="caFingerprint" rules={[{ required: true }]}>
            <Input prefix={<SafetyCertificateOutlined />} placeholder="SHA256:…" />
          </Form.Item>
          <Form.Item
            name="caConfirmed"
            valuePropName="checked"
            rules={[
              {
                validator: (_, value) =>
                  value ? Promise.resolve() : Promise.reject(new Error('请确认企业 CA 指纹')),
              },
            ]}
          >
            <Checkbox>我已通过独立可信渠道核对企业 CA 指纹</Checkbox>
          </Form.Item>
          <Button
            icon={probeDone ? <CheckCircleOutlined /> : <ApiOutlined />}
            onClick={probeConnection}
          >
            {probeDone ? '能力探测已通过' : '测试连接与能力'}
          </Button>
          {probeDone ? (
            <Steps
              size="small"
              current={5}
              items={['DNS', 'TLS', '认证', 'API 能力', 'Webhook'].map((title) => ({
                title,
                status: 'finish',
              }))}
              style={{ marginTop: 20 }}
            />
          ) : null}
        </Form>
      </WhiteDetailDrawer>
    </PageContainer>
  );
}
