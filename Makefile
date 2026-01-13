.PHONY: pdf pdf-en pdf-fr clean

# Build both PDFs
pdf: pdf-en pdf-fr

# English PDF
pdf-en:
	cd spec/en && latexmk -xelatex -interaction=nonstopmode -halt-on-error -output-directory=build LiveShark_Spec.tex

# French PDF
pdf-fr:
	cd spec/fr && latexmk -xelatex -interaction=nonstopmode -halt-on-error -output-directory=build LiveShark_Spec.tex

# Clean build artifacts
clean:
	cd spec/en && latexmk -C -output-directory=build LiveShark_Spec.tex || true
	cd spec/fr && latexmk -C -output-directory=build LiveShark_Spec.tex || true
	rm -rf spec/en/build spec/fr/build
