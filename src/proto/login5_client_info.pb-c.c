/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: login5_client_info.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "login5_client_info.pb-c.h"
void   spotify__login5__v3__client_info__init
                     (Spotify__Login5__V3__ClientInfo         *message)
{
  static const Spotify__Login5__V3__ClientInfo init_value = SPOTIFY__LOGIN5__V3__CLIENT_INFO__INIT;
  *message = init_value;
}
size_t spotify__login5__v3__client_info__get_packed_size
                     (const Spotify__Login5__V3__ClientInfo *message)
{
  assert(message->base.descriptor == &spotify__login5__v3__client_info__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t spotify__login5__v3__client_info__pack
                     (const Spotify__Login5__V3__ClientInfo *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &spotify__login5__v3__client_info__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t spotify__login5__v3__client_info__pack_to_buffer
                     (const Spotify__Login5__V3__ClientInfo *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &spotify__login5__v3__client_info__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Spotify__Login5__V3__ClientInfo *
       spotify__login5__v3__client_info__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Spotify__Login5__V3__ClientInfo *)
     protobuf_c_message_unpack (&spotify__login5__v3__client_info__descriptor,
                                allocator, len, data);
}
void   spotify__login5__v3__client_info__free_unpacked
                     (Spotify__Login5__V3__ClientInfo *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &spotify__login5__v3__client_info__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor spotify__login5__v3__client_info__field_descriptors[2] =
{
  {
    "client_id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Spotify__Login5__V3__ClientInfo, client_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "device_id",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Spotify__Login5__V3__ClientInfo, device_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned spotify__login5__v3__client_info__field_indices_by_name[] = {
  0,   /* field[0] = client_id */
  1,   /* field[1] = device_id */
};
static const ProtobufCIntRange spotify__login5__v3__client_info__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor spotify__login5__v3__client_info__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "spotify.login5.v3.ClientInfo",
  "ClientInfo",
  "Spotify__Login5__V3__ClientInfo",
  "spotify.login5.v3",
  sizeof(Spotify__Login5__V3__ClientInfo),
  2,
  spotify__login5__v3__client_info__field_descriptors,
  spotify__login5__v3__client_info__field_indices_by_name,
  1,  spotify__login5__v3__client_info__number_ranges,
  (ProtobufCMessageInit) spotify__login5__v3__client_info__init,
  NULL,NULL,NULL    /* reserved[123] */
};