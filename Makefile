IMAGE_NAME=smartnetids

build:
	docker build -t $(IMAGE_NAME) .

run:
	docker run --rm -it -p 8501:8501 -v $(PWD)/data:/app/data -v $(PWD)/datasets:/app/datasets $(IMAGE_NAME)

test:
	docker run --rm -it $(IMAGE_NAME) pytest tests/

clean:
	docker rmi $(IMAGE_NAME) || true

shell:
	docker run --rm -it --entrypoint /bin/bash $(IMAGE_NAME) 