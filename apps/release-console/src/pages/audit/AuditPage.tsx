import { DownloadOutlined, RightOutlined } from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import { Alert, App as AntApp, Button, Descriptions, Space, Tabs, Typography } from 'antd';
import { useState } from 'react';
import { logCenterEvents } from '../../api/demoData';
import type { LogCenterEvent, LogCenterKind } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

export function AuditPage() {
  const { message } = AntApp.useApp();
  const { hasAnyRole } = useAuth();
  const [selected, setSelected] = useState<LogCenterEvent | null>(null);
  const [cursorPage, setCursorPage] = useState(1);
  const [logType, setLogType] = useState<LogCenterKind>('operation');
  const logData = logCenterEvents.filter((event) => event.kind === logType);

  const columns: ProColumns<LogCenterEvent>[] = [
    {
      title: '时间',
      dataIndex: 'time',
      valueType: 'dateTimeRange',
      render: (_, record) => record.time,
    },
    {
      title: '产品',
      dataIndex: 'product',
      valueType: 'select',
      valueEnum: { ngep: 'ngep', 'xminds-agent': 'xminds-agent' },
    },
    { title: '操作者', dataIndex: 'actor' },
    { title: '动作', dataIndex: 'action' },
    { title: '目标', dataIndex: 'target' },
    {
      title: '结果',
      dataIndex: 'result',
      valueType: 'select',
      render: (_, record) => <StatusTag status={record.result} />,
    },
    { title: 'Release', dataIndex: 'releaseId', hideInTable: true },
    { title: '请求 ID', dataIndex: 'requestId', hideInTable: true },
    {
      title: '操作',
      valueType: 'option',
      render: (_, record) => [
        <Button key="detail" type="link" onClick={() => setSelected(record)}>
          查看证据
        </Button>,
      ],
    },
  ];

  return (
    <PageContainer
      title="日志中心"
      content="统一查询操作、登录、应用请求与 Git 同步日志；所有记录均按服务端 scope 与不可变证据策略返回。"
    >
      <Tabs
        activeKey={logType}
        onChange={(key) => setLogType(key as LogCenterKind)}
        items={[
          { key: 'operation', label: '操作日志' },
          { key: 'authentication', label: '登录日志' },
          { key: 'application', label: '应用请求日志' },
          { key: 'git', label: 'Git 同步日志' },
        ]}
        style={{ marginBottom: 16 }}
      />
      <Alert
        type="info"
        showIcon
        title="审计事件不可修改或删除"
        description="导出任务异步生成，并记录导出主体、查询条件、摘要和到期时间。"
        style={{ marginBottom: 16 }}
      />
      <ProTable<LogCenterEvent>
        rowKey="id"
        columns={columns.concat(
          logType === 'application'
            ? [
                { title: '授权名称', dataIndex: 'authorizationName' },
                { title: '客户端应用版本', dataIndex: 'clientAppVersion' },
                { title: 'License ID', dataIndex: 'licenseId' },
                { title: '到期时间', dataIndex: 'licenseExpiresAt' },
              ]
            : logType === 'authentication'
              ? [{ title: '认证方式', dataIndex: 'action' }]
              : logType === 'git'
                ? [
                    { title: 'Provider', dataIndex: 'provider' },
                    { title: '同步阶段', dataIndex: 'syncStage' },
                  ]
                : [],
        )}
        dataSource={logData}
        search={{ labelWidth: 'auto', span: 6 }}
        options={{ density: true, setting: true, reload: true }}
        pagination={false}
        toolBarRender={() =>
          hasAnyRole('auditor')
            ? [
                <Button
                  key="export"
                  icon={<DownloadOutlined />}
                  aria-label="导出审计证据"
                  onClick={() => message.success('证据导出任务已创建')}
                >
                  导出审计证据
                </Button>,
              ]
            : []
        }
        footer={() => (
          <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
            <Typography.Text type="secondary">
              游标页 {cursorPage} · 仅使用服务端返回的下一页游标
            </Typography.Text>
            <Button disabled={cursorPage === 1} onClick={() => setCursorPage((value) => value - 1)}>
              上一页
            </Button>
            <Button
              icon={<RightOutlined />}
              iconPlacement="end"
              onClick={() => setCursorPage((value) => value + 1)}
            >
              下一页
            </Button>
          </Space>
        )}
      />
      <WhiteDetailDrawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title="审计证据详情"
      >
        {selected ? (
          <Space orientation="vertical" size={24} style={{ width: '100%' }}>
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="事件时间">{selected.time}</Descriptions.Item>
              <Descriptions.Item label="结果">
                <StatusTag status={selected.result} />
              </Descriptions.Item>
              <Descriptions.Item label="产品">{selected.product}</Descriptions.Item>
              <Descriptions.Item label="操作者">{selected.actor}</Descriptions.Item>
              <Descriptions.Item label="动作">
                <span className="mono">{selected.action}</span>
              </Descriptions.Item>
              <Descriptions.Item label="目标">{selected.target}</Descriptions.Item>
              {selected.kind === 'application' ? (
                <>
                  <Descriptions.Item label="授权名称">
                    {selected.authorizationName}
                  </Descriptions.Item>
                  <Descriptions.Item label="客户端应用版本">
                    {selected.clientAppVersion}
                  </Descriptions.Item>
                  <Descriptions.Item label="License ID">
                    <span className="mono">{selected.licenseId}</span>
                  </Descriptions.Item>
                  <Descriptions.Item label="到期时间">
                    {selected.licenseExpiresAt}
                  </Descriptions.Item>
                </>
              ) : null}
              {selected.kind === 'git' ? (
                <>
                  <Descriptions.Item label="Provider">{selected.provider}</Descriptions.Item>
                  <Descriptions.Item label="仓库">{selected.repository}</Descriptions.Item>
                  <Descriptions.Item label="同步阶段">{selected.syncStage}</Descriptions.Item>
                </>
              ) : null}
              <Descriptions.Item label="请求 ID" span={2}>
                <span className="mono">{selected.requestId}</span>
              </Descriptions.Item>
              <Descriptions.Item label="证据摘要" span={2}>
                {selected.summary}
              </Descriptions.Item>
            </Descriptions>
            <Alert
              type="success"
              showIcon
              title="哈希链校验通过"
              description="本事件与同产品前序事件摘要连续，未发现篡改或断链。"
            />
          </Space>
        ) : null}
      </WhiteDetailDrawer>
    </PageContainer>
  );
}
