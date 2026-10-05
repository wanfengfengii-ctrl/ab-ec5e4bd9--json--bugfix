.PHONY: up verify test smoke down clean

up:            ## 启动网关（HOST_PORT=9090 make up 可改宿主机端口）
	docker compose up --build app

verify:        ## 一次性验证：构建 + 单元测试 + 签名/压缩/并发防重放冒烟
	docker compose up --build --exit-code-from verify --abort-on-container-exit verify

test:          ## 本地单元测试（无需 Docker）
	python3 -m unittest discover -s tests -t .

smoke:         ## 本地完整验证（需网关已运行，GATEWAY_URL=http://127.0.0.1:8000 make smoke）
	GATEWAY_URL=$${GATEWAY_URL:-http://127.0.0.1:8000} python3 -m verify.run

down:          ## 停止服务
	docker compose down

clean:         ## 停止并清空持久化 nonce 数据
	docker compose down -v
