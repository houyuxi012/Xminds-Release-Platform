import { ArrowLeftOutlined, CheckOutlined, RocketOutlined, StopOutlined } from '@ant-design/icons';
import { PageContainer, ProCard } from '@ant-design/pro-components';
import { Alert, App as AntApp, Button, Descriptions, Space, Timeline, Typography } from 'antd';
import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { releases } from '../../api/demoData';
import type { ReleaseStatus } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';
import { StatusTag } from '../../components/StatusTag';

export function ReleaseDetailPage() {
  const navigate = useNavigate();
  const { message, modal } = AntApp.useApp();
  const { releaseId } = useParams();
  const { hasAnyRole, principal } = useAuth();
  const release = releases.find((item) => item.id === releaseId) || releases[0];
  const [status, setStatus] = useState<ReleaseStatus>(release.status);
  const canApprove =
    hasAnyRole('admin', 'approver') &&
    principal?.id !== release.submittedBy &&
    status === 'submitted';
  const canPublish = hasAnyRole('admin', 'publisher') && status === 'approved';
  const separationBlocked = principal?.id === release.submittedBy && status === 'submitted';

  const approve = () => {
    modal.confirm({
      title: `批准 Release ${release.version}`,
      content: '批准后发布内容保持不可变；审批人与提交人必须不同。',
      okText: '确认批准',
      cancelText: '取消',
      onOk: () => {
        setStatus('approved');
        message.success('审批已记录，可开始发布');
      },
    });
  };

  const publish = () => {
    modal.confirm({
      title: `发布 ${release.version} 至 ${release.channel}`,
      content: '将签名可信目录并同步到所有健康分发端点。该操作会产生不可变审计证据。',
      okText: '确认发布',
      cancelText: '取消',
      onOk: () => {
        setStatus('published');
        message.success('Release 已发布，端点同步完成');
      },
    });
  };

  return (
    <PageContainer
      title={release.version}
      subTitle={<span className="mono">{release.id}</span>}
      tags={<StatusTag status={status} />}
      content={`${release.product} · ${release.channel}`}
      extra={[
        <Button key="back" icon={<ArrowLeftOutlined />} onClick={() => navigate('/releases')}>
          返回
        </Button>,
        ...(canApprove
          ? [
              <Button
                key="approve"
                type="primary"
                icon={<CheckOutlined />}
                aria-label="批准发布"
                onClick={approve}
              >
                批准发布
              </Button>,
            ]
          : []),
        ...(canPublish
          ? [
              <Button
                key="publish"
                type="primary"
                icon={<RocketOutlined />}
                aria-label="开始发布"
                onClick={publish}
              >
                开始发布
              </Button>,
            ]
          : []),
      ]}
    >
      {separationBlocked ? (
        <Alert
          type="warning"
          showIcon
          title="职责分离：不能审批本人提交的 Release"
          description="请由授权产品范围内的其他审批者完成审批。API 会再次执行权威校验。"
          style={{ marginBottom: 16 }}
        />
      ) : null}
      {status === 'failed' ? (
        <Alert
          type="error"
          showIcon
          title="目录发布失败（ENDPOINT_DIGEST_MISMATCH）"
          description="目标端 timestamp 摘要回读不一致 · 请求 ID：req_01J5A0KQ12XM"
          action={<Button icon={<RocketOutlined />}>重试发布</Button>}
          style={{ marginBottom: 16 }}
        />
      ) : null}

      <div className="content-grid">
        <Space orientation="vertical" size={16} style={{ width: '100%' }}>
          <ProCard title="Release 信息" className="page-card">
            <Descriptions column={2} bordered size="small">
              <Descriptions.Item label="产品">{release.product}</Descriptions.Item>
              <Descriptions.Item label="版本">{release.version}</Descriptions.Item>
              <Descriptions.Item label="通道">{release.channel}</Descriptions.Item>
              <Descriptions.Item label="提交者">{release.submittedBy}</Descriptions.Item>
              <Descriptions.Item label="Release Notes" span={2}>
                {release.notes}
              </Descriptions.Item>
              <Descriptions.Item label="制品" span={2}>
                {release.artifacts.join('、')}
              </Descriptions.Item>
            </Descriptions>
          </ProCard>
          <ProCard title="发布校验" className="page-card">
            <Space orientation="vertical">
              <Typography.Text>
                <CheckOutlined style={{ color: '#52c41a' }} /> Manifest 契约与产品范围校验通过
              </Typography.Text>
              <Typography.Text>
                <CheckOutlined style={{ color: '#52c41a' }} /> 制品服务端 SHA-256 校验通过
              </Typography.Text>
              <Typography.Text>
                <CheckOutlined style={{ color: '#52c41a' }} /> 在线签名角色可用，root 保持离线
              </Typography.Text>
              <Typography.Text>
                <StopOutlined style={{ color: '#faad14' }} /> 提交者自审批已被策略禁止
              </Typography.Text>
            </Space>
          </ProCard>
        </Space>
        <ProCard title="状态与发布尝试" className="page-card">
          <Timeline
            items={[
              {
                color: 'green',
                content: (
                  <>
                    <strong>创建草稿</strong>
                    <div className="timeline-code">2026-08-20 13:31 · alice</div>
                  </>
                ),
              },
              {
                color: 'green',
                content: (
                  <>
                    <strong>提交审批</strong>
                    <div className="timeline-code">2026-08-20 13:46 · req_01J5A0JH8Q4V</div>
                  </>
                ),
              },
              {
                color: status === 'submitted' ? 'blue' : 'green',
                content: (
                  <>
                    <strong>{status === 'submitted' ? '等待不同审批者' : '审批通过'}</strong>
                    <div className="timeline-code">职责分离策略已启用</div>
                  </>
                ),
              },
              ...(status === 'published'
                ? [
                    {
                      color: 'green',
                      content: (
                        <>
                          <strong>目录签名与分发完成</strong>
                          <div className="timeline-code">
                            targets · snapshot · timestamp · revocation
                          </div>
                        </>
                      ),
                    },
                  ]
                : []),
            ]}
          />
        </ProCard>
      </div>
    </PageContainer>
  );
}
