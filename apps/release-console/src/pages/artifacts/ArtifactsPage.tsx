import {
  InboxOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import {
  Alert,
  App as AntApp,
  Button,
  Descriptions,
  Modal,
  Progress,
  Space,
  Typography,
  Upload,
} from 'antd';
import { useRef, useState } from 'react';
import { artifacts as initialArtifacts } from '../../api/demoData';
import type { Artifact } from '../../api/types';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

export function ArtifactsPage() {
  const { message } = AntApp.useApp();
  const [artifacts, setArtifacts] = useState(initialArtifacts);
  const [selected, setSelected] = useState<Artifact | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const uploadProgressRef = useRef(0);
  const [quarantineError, setQuarantineError] = useState(false);

  const columns: ProColumns<Artifact>[] = [
    {
      title: '制品',
      dataIndex: 'filename',
      render: (_, record) => (
        <div className="table-primary-cell">
          <Typography.Text strong>{record.filename}</Typography.Text>
          <span>
            {record.product} · {record.version}
          </span>
        </div>
      ),
    },
    {
      title: '产品',
      dataIndex: 'product',
      valueType: 'select',
      valueEnum: { ngep: 'ngep', 'xminds-agent': 'xminds-agent' },
    },
    { title: '大小', dataIndex: 'size', search: false },
    {
      title: 'SHA-256',
      dataIndex: 'sha256',
      search: false,
      render: (value) => <span className="mono">{String(value)}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      valueType: 'select',
      valueEnum: { verified: '校验通过', uploading: '上传中', quarantined: '已隔离' },
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

  const simulateUpload = () => {
    if (uploadProgressRef.current === 0) {
      uploadProgressRef.current = 62;
      setUploadProgress(62);
      message.info('网络中断，已安全保存 62% 分块进度');
      return;
    }
    setArtifacts((current) => [
      {
        id: 'artifact-uploaded',
        product: 'ngep',
        filename: 'ngep-desktop-1.2.4-arm64.dmg',
        version: '1.2.4',
        size: '188.1 MiB',
        sha256: '6f45de1728b2e019f8d2…550b9dca',
        status: 'verified',
        progress: 100,
        updatedAt: '刚刚',
      },
      ...current,
    ]);
    setUploadOpen(false);
    uploadProgressRef.current = 0;
    setUploadProgress(0);
    message.success('上传完成，服务端 SHA-256 校验通过');
  };

  return (
    <PageContainer
      title="制品"
      content="支持 24 小时可恢复分块上传、服务端独立摘要校验和不可变内容寻址存储。"
    >
      {quarantineError ? (
        <Alert
          type="error"
          showIcon
          closable
          onClose={() => setQuarantineError(false)}
          title="制品摘要不匹配，已隔离"
          description="ARTIFACT_DIGEST_MISMATCH · 请求 ID：req_01J5A1M8TR2N。请重新计算本地 SHA-256 后发起新上传。"
          action={
            <Button icon={<ReloadOutlined />} onClick={() => setUploadOpen(true)}>
              重新上传
            </Button>
          }
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <ProTable<Artifact>
        rowKey="id"
        columns={columns}
        dataSource={artifacts}
        search={{ labelWidth: 'auto' }}
        options={{ density: true, setting: true, reload: true }}
        pagination={{ pageSize: 10, showSizeChanger: false }}
        toolBarRender={() => [
          <Button key="quarantine" onClick={() => setQuarantineError(true)}>
            演示隔离错误
          </Button>,
          <Button
            key="upload"
            type="primary"
            icon={<PlusOutlined />}
            aria-label="上传制品"
            onClick={() => setUploadOpen(true)}
          >
            上传制品
          </Button>,
        ]}
      />

      <Modal
        title="可恢复分块上传"
        open={uploadOpen}
        onCancel={() => setUploadOpen(false)}
        onOk={simulateUpload}
        cancelText="取消"
        okText={uploadProgress === 62 ? '继续上传' : '开始上传'}
      >
        <Upload.Dragger beforeUpload={() => false} showUploadList={false} aria-label="选择制品文件">
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p>拖拽制品到此处，或点击选择文件</p>
          <p className="ant-upload-hint">
            单个制品最大 20 GiB；上传完成后由服务端重新计算 SHA-256。
          </p>
        </Upload.Dragger>
        {uploadProgress > 0 ? (
          <div style={{ marginTop: 20 }}>
            <Space style={{ marginBottom: 8 }}>
              <SafetyCertificateOutlined style={{ color: '#1677ff' }} />
              <Typography.Text>ngep-desktop-1.2.4-arm64.dmg</Typography.Text>
            </Space>
            <Progress percent={uploadProgress} status="exception" />
            {uploadProgress === 62 ? (
              <Alert type="warning" showIcon title="连接已中断，可从第 248 个分块继续" />
            ) : null}
          </div>
        ) : null}
      </Modal>

      <WhiteDetailDrawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title="制品详情"
      >
        {selected ? (
          <Descriptions bordered size="small" column={2} title={selected.filename}>
            <Descriptions.Item label="产品">{selected.product}</Descriptions.Item>
            <Descriptions.Item label="版本">{selected.version}</Descriptions.Item>
            <Descriptions.Item label="状态">
              <StatusTag status={selected.status} />
            </Descriptions.Item>
            <Descriptions.Item label="大小">{selected.size}</Descriptions.Item>
            <Descriptions.Item label="SHA-256" span={2}>
              <span className="mono">{selected.sha256}</span>
            </Descriptions.Item>
            <Descriptions.Item label="存储策略" span={2}>
              内容寻址、服务端加密、最终对象不可删除
            </Descriptions.Item>
          </Descriptions>
        ) : null}
      </WhiteDetailDrawer>
    </PageContainer>
  );
}
