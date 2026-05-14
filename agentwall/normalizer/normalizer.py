from __future__ import annotations

from dataclasses import dataclass, field

from agentwall.core.payload import NormalizedPayload
from agentwall.normalizer.encoding import (
    DecodedVariant,
    try_base64_decode,
    try_hex_decode,
    try_rot13_decode,
)
from agentwall.normalizer.models import NormalizationStep
from agentwall.normalizer.structure import flatten_json, strip_html, strip_markdown
from agentwall.normalizer.unicode import normalize_unicode
from agentwall.normalizer.whitespace import collapse_whitespace


@dataclass
class NormalizationResult:
    canonical: NormalizedPayload
    variants: list[NormalizedPayload] = field(default_factory=list)
    steps: list[NormalizationStep] = field(default_factory=list)


class Normalizer:
    def normalize(self, payload: NormalizedPayload) -> NormalizationResult:
        steps: list[NormalizationStep] = []
        text = payload.text

        if not text:
            return NormalizationResult(canonical=payload, variants=[payload], steps=[])

        json_flat = flatten_json(text)
        if json_flat is not None and json_flat != text:
            text = json_flat
            steps.append(NormalizationStep("flatten_json", "JSON structure flattened"))

        html_stripped = strip_html(text)
        if html_stripped != text:
            text = html_stripped
            steps.append(NormalizationStep("strip_html", "HTML tags removed"))

        md_stripped = strip_markdown(text)
        if md_stripped != text:
            text = md_stripped
            steps.append(NormalizationStep("strip_markdown", "Markdown formatting stripped"))

        normalized = normalize_unicode(text)
        if normalized != text:
            steps.append(NormalizationStep("unicode_normalize", "NFKC + zero-width strip"))
        text = normalized

        collapsed = collapse_whitespace(text)
        if collapsed != text:
            steps.append(NormalizationStep("collapse_whitespace", "Whitespace collapsed"))
        text = collapsed

        canonical = payload.model_copy(update={"text": text})

        variants: list[NormalizedPayload] = [payload, canonical]

        decoded_variants: list[DecodedVariant] = []
        decoded_variants.extend(try_base64_decode(text))
        rot13 = try_rot13_decode(text)
        if rot13:
            decoded_variants.append(DecodedVariant(text=rot13, method="rot13"))
        decoded_variants.extend(try_hex_decode(text))

        for dv in decoded_variants:
            steps.append(NormalizationStep(f"decode_{dv.method}", f"Decoded via {dv.method}"))
            variant = payload.model_copy(update={"text": dv.text})
            variants.append(variant)

        return NormalizationResult(canonical=canonical, variants=variants, steps=steps)
