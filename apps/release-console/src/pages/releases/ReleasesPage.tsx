import { PlusOutlined } from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import { Alert, App as AntApp, Button, Form, Input, Select, Space, Steps, Typography } from 'antd';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { releases as initialReleases } from '../../api/demoData';
import type { ReleaseRecord } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

const wizardSteps = ['基本信息', '选择制品', '发布配置', '确认提交'];
const wizardStepFields = [['product', 'version'], ['artifact'], ['channel']] as const;
const initialWizardValues = {
  product: 'ngep',
  version: '1.2.4',
  artifact: 'ngep-desktop-1.2.4-arm64.dmg',
  channel: 'stable',
  notes: '提升企业网络环境下的更新可靠性。',
};

export function ReleasesPage() {
  const navigate = useNavigate();
  const { message } = AntApp.useApp();
  const { hasAnyRole, principal } = useAuth();
  const [records, setRecords] = useState(initialReleases);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [wizardValues, setWizardValues] = useState(initialWizardValues);
  const [form] = Form.useForm();

  const columns: ProColumns<ReleaseRecord>[] = [
    {
      title: '版本',
      dataIndex: 'version',
      render: (_, record) => (
        <div className="table-primary-cell">
          <Typography.Text strong>{record.version}</Typography.Text>
          <span className="mono">{record.id}</span>
        </div>
      ),
    },
    {
      title: '产品',
      dataIndex: 'product',
      valueType: 'select',
      valueEnum: { ngep: 'ngep', 'xminds-agent': 'xminds-agent' },
    },
    {
      title: '通道',
      dataIndex: 'channel',
      valueType: 'select',
      valueEnum: { stable: 'stable', beta: 'beta' },
    },
    {
      title: '状态',
      dataIndex: 'status',
      valueType: 'select',
      valueEnum: { draft: '草稿', submitted: '待审批', published: '已发布', failed: '失败' },
      render: (_, record) => <StatusTag status={record.status} />,
    },
    { title: '提交人', dataIndex: 'submittedBy' },
    { title: '更新时间', dataIndex: 'updatedAt', search: false },
    {
      title: '操作',
      valueType: 'option',
      render: (_, record) => [
        <Button key="detail" type="link" onClick={() => navigate(`/releases/${record.id}`)}>
          查看详情
        </Button>,
      ],
    },
  ];

  const closeWizard = () => {
    setWizardOpen(false);
    setCurrentStep(0);
    setWizardValues(initialWizardValues);
    form.resetFields();
  };

  const next = async () => {
    if (currentStep < 3) {
      try {
        await form.validateFields([...wizardStepFields[currentStep]]);
      } catch {
        return;
      }
      setCurrentStep((value) => value + 1);
      return;
    }
    let values: typeof initialWizardValues;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    setRecords((current) => [
      {
        id: 'release-new',
        product: values.product || 'ngep',
        version: values.version || '1.2.4',
        channel: values.channel || 'stable',
        status: 'submitted',
        submittedBy: principal.id,
        updatedAt: '刚刚',
        notes: values.notes || 'Release Notes 待补充',
        artifacts: [values.artifact || 'ngep-desktop-1.2.4-arm64.dmg'],
      },
      ...current,
    ]);
    message.success('Release 已提交，等待不同审批者审批');
    closeWizard();
  };

  return (
    <PageContainer
      title="Release"
      content="通过不可变内容、职责分离审批和幂等发布尝试构建可信发布链。"
    >
      <ProTable<ReleaseRecord>
        rowKey="id"
        columns={columns}
        dataSource={records}
        search={{ labelWidth: 'auto' }}
        options={{ density: true, setting: true, reload: true }}
        pagination={{ pageSize: 10, showSizeChanger: false }}
        toolBarRender={() =>
          hasAnyRole('admin', 'publisher')
            ? [
                <Button
                  key="create"
                  type="primary"
                  icon={<PlusOutlined />}
                  aria-label="创建 Release"
                  onClick={() => setWizardOpen(true)}
                >
                  创建 Release
                </Button>,
              ]
            : []
        }
      />

      <WhiteDetailDrawer
        open={wizardOpen}
        onClose={closeWizard}
        title="创建 Release"
        size={840}
        footer={
          <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
            <Button onClick={closeWizard}>取消</Button>
            {currentStep > 0 ? (
              <Button onClick={() => setCurrentStep((value) => value - 1)}>上一步</Button>
            ) : null}
            <Button type="primary" onClick={next}>
              {currentStep === 3 ? '确认提交审批' : '下一步'}
            </Button>
          </Space>
        }
      >
        <Steps
          className="steps"
          current={currentStep}
          items={wizardSteps.map((title) => ({ title }))}
          style={{ marginBottom: 28 }}
        />
        <Form
          form={form}
          layout="vertical"
          initialValues={initialWizardValues}
          onValuesChange={(_, values) => setWizardValues(values)}
        >
          <div hidden={currentStep !== 0}>
            <Form.Item name="product" label="产品" rules={[{ required: true }]}>
              <Select
                options={[
                  { label: 'Next-Gen Enterprise Portal（ngep）', value: 'ngep' },
                  { label: 'Xminds Agent', value: 'xminds-agent' },
                ]}
              />
            </Form.Item>
            <Form.Item name="version" label="版本" rules={[{ required: true }]}>
              <Input placeholder="例如 1.2.4" />
            </Form.Item>
            <Form.Item name="notes" label="Release Notes">
              <Input.TextArea rows={5} />
            </Form.Item>
          </div>
          <div hidden={currentStep !== 1}>
            <Alert
              type="info"
              showIcon
              title="只可选择已完成服务端 SHA-256 校验的制品"
              style={{ marginBottom: 16 }}
            />
            <Form.Item name="artifact" label="制品" rules={[{ required: true }]}>
              <Select
                options={[
                  {
                    label: 'ngep-desktop-1.2.4-arm64.dmg · sha256:6f45…9dca',
                    value: 'ngep-desktop-1.2.4-arm64.dmg',
                  },
                  {
                    label: 'ngep-desktop-1.2.3-arm64.dmg · sha256:8fb9…5d98',
                    value: 'ngep-desktop-1.2.3-arm64.dmg',
                  },
                ]}
              />
            </Form.Item>
          </div>
          <div hidden={currentStep !== 2}>
            <Form.Item name="channel" label="发布通道" rules={[{ required: true }]}>
              <Select
                options={[
                  { label: 'stable', value: 'stable' },
                  { label: 'preview', value: 'preview' },
                ]}
              />
            </Form.Item>
            <Alert
              type="warning"
              showIcon
              title="发布将生成 targets、snapshot、timestamp 与 revocation 目录，并同步至健康端点。"
            />
          </div>
          <div hidden={currentStep !== 3}>
            <Alert
              type="warning"
              showIcon
              title="提交后等待不同审批者审批"
              description="提交者不能批准本人创建的 Release；发布内容在提交后不可修改。"
              style={{ marginBottom: 16 }}
            />
            <div className="release-wizard-summary">
              <Space orientation="vertical" size={8}>
                <Typography.Text>
                  <strong>产品：</strong>
                  {wizardValues.product}
                </Typography.Text>
                <Typography.Text>
                  <strong>版本：</strong>
                  {wizardValues.version}
                </Typography.Text>
                <Typography.Text>
                  <strong>通道：</strong>
                  {wizardValues.channel}
                </Typography.Text>
                <Typography.Text>
                  <strong>制品：</strong>
                  {wizardValues.artifact}
                </Typography.Text>
              </Space>
            </div>
          </div>
        </Form>
      </WhiteDetailDrawer>
    </PageContainer>
  );
}
