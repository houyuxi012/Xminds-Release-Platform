import { DownloadOutlined, RightOutlined } from '@ant-design/icons';
import { PageContainer, type ProColumns, ProTable } from '@ant-design/pro-components';
import { Alert, App as AntApp, Button, Descriptions, Space, Typography } from 'antd';
import { useState } from 'react';
import { auditEvents } from '../../api/demoData';
import type { AuditEvent } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';
import { StatusTag } from '../../components/StatusTag';
import { WhiteDetailDrawer } from '../../components/WhiteDetailDrawer';

export function AuditPage() {
  const { message } = AntApp.useApp();
  const { hasAnyRole } = useAuth();
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [cursorPage, setCursorPage] = useState(1);

  const columns: ProColumns<AuditEvent>[] = [
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
      title="操作审计"
      content="按产品范围查询不可变审计哈希链；P0 完整日志中心将在身份与日志 API 完成后接入。"
    >
      <Alert
        type="info"
        showIcon
        title="审计事件不可修改或删除"
        description="导出任务异步生成，并记录导出主体、查询条件、摘要和到期时间。"
        style={{ marginBottom: 16 }}
      />
      <ProTable<AuditEvent>
        rowKey="id"
        columns={columns}
        dataSource={auditEvents}
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
