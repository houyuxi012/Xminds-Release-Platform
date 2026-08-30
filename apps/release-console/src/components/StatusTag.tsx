import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  SyncOutlined,
} from '@ant-design/icons';
import { Tag } from 'antd';
import type { ReactNode } from 'react';

const statusMap: Record<string, { color: string; label: string; icon: ReactNode }> = {
  active: { color: 'success', label: '已启用', icon: <CheckCircleOutlined /> },
  inactive: { color: 'default', label: '已停用', icon: <CloseCircleOutlined /> },
  verified: { color: 'success', label: '校验通过', icon: <CheckCircleOutlined /> },
  uploading: { color: 'processing', label: '上传中', icon: <SyncOutlined spin /> },
  quarantined: { color: 'error', label: '已隔离', icon: <CloseCircleOutlined /> },
  draft: { color: 'default', label: '草稿', icon: <ClockCircleOutlined /> },
  submitted: { color: 'warning', label: '待审批', icon: <ClockCircleOutlined /> },
  approved: { color: 'blue', label: '已批准', icon: <CheckCircleOutlined /> },
  publishing: { color: 'processing', label: '发布中', icon: <SyncOutlined spin /> },
  published: { color: 'success', label: '已发布', icon: <CheckCircleOutlined /> },
  failed: { color: 'error', label: '失败', icon: <CloseCircleOutlined /> },
  healthy: { color: 'success', label: '健康', icon: <CheckCircleOutlined /> },
  attention: { color: 'warning', label: '需关注', icon: <ExclamationCircleOutlined /> },
  degraded: { color: 'warning', label: '性能下降', icon: <ExclamationCircleOutlined /> },
  offline: { color: 'error', label: '离线', icon: <CloseCircleOutlined /> },
  success: { color: 'success', label: '成功', icon: <CheckCircleOutlined /> },
  denied: { color: 'warning', label: '已拒绝', icon: <ExclamationCircleOutlined /> },
};

export function StatusTag({ status }: { status: string }) {
  const item = statusMap[status] || { color: 'default', label: status, icon: null };
  return (
    <Tag color={item.color} icon={item.icon}>
      {item.label}
    </Tag>
  );
}
