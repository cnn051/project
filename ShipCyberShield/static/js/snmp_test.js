/**
 * SNMP 테스트 기능을 위한 JavaScript
 */

// SNMP 버전 선택에 따라 필드 표시
document.addEventListener('DOMContentLoaded', function() {
    // SNMP 버전 선택 이벤트 리스너
    const snmpVersion = document.getElementById('snmpVersion');
    if (snmpVersion) {
        snmpVersion.addEventListener('change', function() {
            const snmpv3Settings = document.getElementById('snmpv3Settings');
            if (this.value === '3') {
                snmpv3Settings.classList.remove('d-none');
            } else {
                snmpv3Settings.classList.add('d-none');
            }
        });
    }
    
    // SNMP 테스트 폼 제출 처리
    const snmpTestForm = document.getElementById('snmpTestForm');
    if (snmpTestForm) {
        snmpTestForm.addEventListener('submit', function(e) {
            e.preventDefault();
            runSnmpTest();
        });
    }
});

/**
 * 자산 상세정보에서 SNMP 테스트 모달 열기
 */
function openSnmpTest(assetId, ipAddress) {
    const snmpAssetId = document.getElementById('snmpAssetId');
    const snmpIpAddress = document.getElementById('snmpIpAddress');
    
    if (snmpAssetId && snmpIpAddress) {
        snmpAssetId.value = assetId;
        snmpIpAddress.value = ipAddress || '';
    }
    
    // 결과 영역 초기화
    const resultsArea = document.getElementById('snmpTestResults');
    if (resultsArea) {
        resultsArea.innerHTML = '<p class="text-muted">테스트를 실행하면 결과가 여기에 표시됩니다.</p>';
    }
    
    // 모니터링 추가 버튼 비활성화
    const addToMonitoringBtn = document.getElementById('addToMonitoring');
    if (addToMonitoringBtn) {
        addToMonitoringBtn.disabled = true;
    }
    
    // 모달 표시
    const modal = new bootstrap.Modal(document.getElementById('snmpTestModal'));
    modal.show();
}

/**
 * SNMP 테스트 실행
 */
function runSnmpTest() {
    const assetId = document.getElementById('snmpAssetId').value;
    const ipAddress = document.getElementById('snmpIpAddress').value;
    const community = document.getElementById('snmpCommunity').value;
    const port = document.getElementById('snmpPort').value;
    const version = document.getElementById('snmpVersion').value;
    const testType = document.getElementById('snmpTestType').value;
    
    // SNMPv3 설정
    let snmpv3Data = {};
    if (version === '3') {
        snmpv3Data = {
            username: document.getElementById('snmpUsername').value,
            authProtocol: document.getElementById('snmpAuthProtocol').value,
            authPassword: document.getElementById('snmpAuthPassword').value
        };
    }
    
    // 결과 영역 업데이트
    const resultsArea = document.getElementById('snmpTestResults');
    resultsArea.innerHTML = '<div class="d-flex justify-content-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    
    // 테스트 실행 버튼 비활성화
    const testButton = document.getElementById('runSnmpTest');
    testButton.disabled = true;
    testButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 테스트 실행 중...';
    
    // 서버에 SNMP 테스트 요청
    fetch('/api/snmp/test', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            asset_id: assetId,
            ip_address: ipAddress,
            community: community,
            port: port,
            version: version,
            test_type: testType,
            snmpv3: snmpv3Data
        })
    })
    .then(response => response.json())
    .then(data => {
        // 테스트 결과 표시
        displaySnmpTestResults(data);
    })
    .catch(error => {
        resultsArea.innerHTML = `<div class="alert alert-danger">
            <i class="fas fa-exclamation-triangle me-2"></i>
            테스트 중 오류 발생: ${error.message || '서버 연결 실패'}
        </div>`;
    })
    .finally(() => {
        // 테스트 실행 버튼 다시 활성화
        testButton.disabled = false;
        testButton.innerHTML = '<i class="fas fa-play-circle me-2"></i>테스트 실행';
    });
}

/**
 * SNMP 테스트 결과 표시
 */
function displaySnmpTestResults(data) {
    const resultsArea = document.getElementById('snmpTestResults');
    const addToMonitoringBtn = document.getElementById('addToMonitoring');
    
    if (data.success) {
        // 테스트 성공
        let resultsHtml = `<div class="alert alert-success mb-3">
            <i class="fas fa-check-circle me-2"></i>
            SNMP 연결 성공: ${data.ip_address}
        </div>`;
        
        // 시스템 정보 표시
        if (data.system_info) {
            resultsHtml += `<h6>시스템 정보</h6>
            <table class="table table-sm table-dark">
                <tbody>
                    <tr>
                        <th width="40%">시스템 이름</th>
                        <td>${data.system_info.name || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>설명</th>
                        <td>${data.system_info.description || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>가동 시간</th>
                        <td>${data.system_info.uptime || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>위치</th>
                        <td>${data.system_info.location || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>연락처</th>
                        <td>${data.system_info.contact || 'N/A'}</td>
                    </tr>
                </tbody>
            </table>`;
        }
        
        // 리소스 정보 표시
        if (data.resources) {
            resultsHtml += `<h6 class="mt-3">리소스 정보</h6>
            <table class="table table-sm table-dark">
                <tbody>
                    <tr>
                        <th width="40%">CPU 부하 (1분)</th>
                        <td>${data.resources.cpu_load_1min !== undefined ? data.resources.cpu_load_1min : 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>메모리 사용률</th>
                        <td>${data.resources.memory_usage !== undefined ? data.resources.memory_usage + '%' : 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>디스크 사용률</th>
                        <td>${data.resources.disk_usage !== undefined ? data.resources.disk_usage + '%' : 'N/A'}</td>
                    </tr>
                </tbody>
            </table>`;
        }
        
        // 네트워크 인터페이스 정보 표시
        if (data.interfaces && data.interfaces.length > 0) {
            resultsHtml += `<h6 class="mt-3">네트워크 인터페이스</h6>
            <table class="table table-sm table-dark">
                <thead>
                    <tr>
                        <th>이름</th>
                        <th>상태</th>
                        <th>입력 트래픽</th>
                        <th>출력 트래픽</th>
                    </tr>
                </thead>
                <tbody>`;
            
            data.interfaces.forEach(iface => {
                resultsHtml += `<tr>
                    <td>${iface.name || 'Unknown'}</td>
                    <td>${iface.status === 'up' ? '<span class="badge bg-success">작동 중</span>' : '<span class="badge bg-danger">중지됨</span>'}</td>
                    <td>${formatBytes(iface.in_octets)}</td>
                    <td>${formatBytes(iface.out_octets)}</td>
                </tr>`;
            });
            
            resultsHtml += `</tbody></table>`;
        }
        
        resultsArea.innerHTML = resultsHtml;
        
        // 모니터링 추가 버튼 활성화
        addToMonitoringBtn.disabled = false;
    } else {
        // 테스트 실패
        resultsArea.innerHTML = `<div class="alert alert-danger">
            <i class="fas fa-exclamation-triangle me-2"></i>
            SNMP 연결 실패: ${data.message || '알 수 없는 오류'}
        </div>
            
        <div class="alert alert-info mt-3">
            <h6><i class="fas fa-info-circle me-2"></i>문제 해결 방법:</h6>
            <ul>
                <li>IP 주소가 올바른지 확인하세요.</li>
                <li>대상 시스템에 SNMP 서비스가 실행 중인지 확인하세요.</li>
                <li>SNMP 커뮤니티 문자열이 올바른지 확인하세요.</li>
                <li>SNMP 포트(기본값: 161)가 방화벽에서 차단되어 있지 않은지 확인하세요.</li>
            </ul>
        </div>`;
        
        // 모니터링 추가 버튼 비활성화
        addToMonitoringBtn.disabled = true;
    }
}

/**
 * 바이트 수를 사람이 읽기 쉬운 형식으로 변환
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === undefined || bytes === null) return 'N/A';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * 자산을 모니터링에 추가
 */
function addAssetToMonitoring() {
    const assetId = document.getElementById('snmpAssetId').value;
    
    // 서버에 모니터링 추가 요청
    fetch('/api/monitoring/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            asset_id: assetId
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // 성공 메시지 표시
            const resultsArea = document.getElementById('snmpTestResults');
            resultsArea.innerHTML += `<div class="alert alert-success mt-3">
                <i class="fas fa-check-circle me-2"></i>
                자산이 모니터링에 추가되었습니다.
            </div>`;
            
            // 모니터링 추가 버튼 비활성화
            const addToMonitoringBtn = document.getElementById('addToMonitoring');
            addToMonitoringBtn.disabled = true;
            
            // 자산 목록 업데이트 (필요시)
            setTimeout(() => {
                window.location.reload();
            }, 2000);
        } else {
            // 오류 메시지 표시
            const resultsArea = document.getElementById('snmpTestResults');
            resultsArea.innerHTML += `<div class="alert alert-danger mt-3">
                <i class="fas fa-exclamation-triangle me-2"></i>
                모니터링 추가 실패: ${data.message || '알 수 없는 오류'}
            </div>`;
        }
    })
    .catch(error => {
        const resultsArea = document.getElementById('snmpTestResults');
        resultsArea.innerHTML += `<div class="alert alert-danger mt-3">
            <i class="fas fa-exclamation-triangle me-2"></i>
            모니터링 추가 중 오류 발생: ${error.message || '서버 연결 실패'}
        </div>`;
    });
}