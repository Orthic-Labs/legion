// gRPC framework pack: protobuf/gRPC contract and auth/interceptor coverage,
// deadline/streaming semantics.

export default Object.freeze({
  id: 'framework.grpc',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((m) => /grpc|protobuf/.test(JSON.stringify(m)))
      || (projection?.files ?? []).some((file) => file.endsWith('.proto'));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      // RPC service without visible auth interceptor.
      if (/service\s+\w+\s*\{/.test(text) && !/auth|interceptor|metadata/.test(text)) {
        observations.push({ ruleId: 'grpc.service-no-auth', severityHint: 'medium', claim: 'gRPC service has no visible auth interceptor.', file });
      }
      // Server without deadline configuration.
      if (/grpc\.NewServer\s*\(/.test(text) && !/KeepaliveParams|EnforcementPolicy|MaxRecvMsgSize/.test(text)) {
        observations.push({ ruleId: 'grpc.server-no-limits', severityHint: 'medium', claim: 'gRPC server has no visible limit/deadline configuration.', file });
      }
      // Streaming RPC without flow control.
      if (/rpc\s+\w+\s*\(\s*stream|stream\s+\w+\s*\)\s*(?:returns)?/.test(text) && !/MaxRecvMsgSize|recv\(\)/.test(text)) {
        observations.push({ ruleId: 'grpc.unbounded-stream', severityHint: 'low', claim: 'Streaming RPC has no visible flow control.', file });
      }
    }
    return observations;
  },
});
