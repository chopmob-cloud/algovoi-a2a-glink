# Audio bandwidth benchmark plan

## Metrics

For every transmission, record:

- logical payload bytes;
- exact transmitted envelope bytes;
- compressed bytes, if compression is enabled;
- audio samples and duration;
- decoded payload bytes;
- end-to-end wall-clock time;
- decode success, corruption, and retransmission count.

Report effective throughput as decoded application bytes divided by elapsed
transmission time. Do not treat WAV file size as network bandwidth.

## Test matrix

- normal, fast, and fastest modes;
- audible and ultrasonic modes where supported;
- direct room audio and recorded/replayed audio;
- distance, volume, speech, and background-noise variations;
- compact binary, JSON, and compressed representations;
- signed messages with tamper and replay tests.

## Acceptance rule

An optimisation is useful only if its throughput improvement is accompanied by
an explicitly measured reliability result. A mode that is faster but loses
messages in realistic conditions should be selected only for non-critical
demonstrations, never silently for signed negotiations or payment-related data.
