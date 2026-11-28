# Online lookup: privacy policy change (draft for Hoan and the lawyer)

Status: **draft, not live.** ADR 0004 step 5 (decided with Hoan 27/11) turns the online lookup on by
default and changes the privacy policy from "sends nothing" to what is true, in the same release. The
code is in place but switched off (`app/src-tauri/src/lookup.rs`, `AVAILABLE = false`), so no
request is made until this text is on the privacy page.

## To go live (one release)

1. Hoan (and the lawyer reviewing the legal pages) approve the text below; it goes on
   craftthecode.dev/genra/privacy in Vietnamese and English.
2. Load the `known_bad` table and switch Workers Logs off or down (backend/README.md).
3. Flip `AVAILABLE` to true in `lookup.rs`; the switch "Kiểm tra trực tuyến" then appears in Cài đặt,
   on by default.
4. CHANGELOG and the user notes say it plainly ("Genra kiểm tra thêm với danh sách trực tuyến…").

## Text to add to the policy (Vietnamese)

> **Kiểm tra trực tuyến (bật sẵn, tắt được trong Cài đặt).** Khi bạn kiểm tra một tệp, hoặc Canh gác
> thấy một tệp mới, mà Genra chưa thấy gì đáng ngờ trên máy, Genra gửi đến máy chủ của Genra
> (genra-api.craftthecode.dev) **5 ký tự đầu của dấu vân tay SHA-256 của tệp**. Năm ký tự này chung cho
> khoảng một trong một triệu tệp, nên không cho biết đó là tệp nào. Máy chủ trả về danh sách mã độc
> đã biết có cùng 5 ký tự đầu; việc so khớp làm trên máy bạn. Genra **không bao giờ gửi tệp, tên
> tệp, hay dấu vân tay đầy đủ** trong việc này.
>
> Như mọi kết nối Internet, yêu cầu mang địa chỉ IP của máy bạn. Máy chủ không ghi lại địa chỉ IP
> hay 5 ký tự đã hỏi; câu trả lời giống nhau cho mọi người và được lưu đệm (cache) bởi Cloudflare,
> nhà cung cấp hạ tầng của Genra.
>
> Danh sách mã độc lấy từ các nguồn công khai (abuse.ch). Một tệp có trong danh sách chỉ được báo
> "Đáng ngờ" và không bao giờ bị tự động chuyển đi.

## Text to add to the policy (English)

> **Online check (on by default, can be turned off in Settings).** When you check a file, or the
> folder guard sees a new one, and nothing on your computer flagged it, Genra sends Genra's server
> (genra-api.craftthecode.dev) **the first 5 characters of the file's SHA-256 fingerprint**. Those
> 5 characters are shared by about one file in a million, so they do not say which file it is. The
> server answers with the known-malware fingerprints that start the same way; the comparison is made
> on your computer. Genra **never sends the file, its name, or its full fingerprint** for this.
>
> Like any Internet connection, the request carries your computer's IP address. The server keeps no
> record of IP addresses or of the characters asked about; the answer is the same for everyone and
> is cached by Cloudflare, Genra's hosting provider.
>
> The malware list comes from public sources (abuse.ch). A file on the list is only marked
> "Suspicious" and is never moved automatically.

## The sentence that changes

The policy's current "Genra sends nothing unless you ask it to" (or its equivalent) becomes:
"Genra never sends your files. To check a file it may send the first 5 characters of its
fingerprint, shared by about one file in a million (see Online check)."

## Points for the lawyer (Nghị định 13/2023/NĐ-CP)

- Whether a 20-bit hash prefix together with an IP address counts as personal data under Decree 13.
  The prefix alone identifies nothing; the IP is processed only in transit by Cloudflare.
- Cloudflare as processor and cross-border transfer (servers outside Vietnam).
- On-by-default with an off switch, versus asking at first run.
