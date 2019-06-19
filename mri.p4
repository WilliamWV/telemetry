/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<5>  IPV4_OPTION_MRI = 31;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE = 2;

#define MAX_HOPS 9
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> uint_32;
typedef bit<16> uint_16;

const ip4Addr_t STATS_CONTROLLER_IPV4 = 0x0a000263; // 10.0.2.99

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header mri_t {
    bit<16>  count;
}

header switch_t {
    uint_16 swid;           //id do distpositivo
    uint_32 qdepth;         //tamanho da fila
    uint_32 timestamp;      //timestamp -> ingresso na fila 
    uint_32 timedelta;      //delay do salto
    uint_16 rule_id;        //regra de encaminhamento
}

struct ingress_metadata_t {
    bit<16>  count;
    uint_16  rule_id;
    bit<1>   last_hop;
}

struct parser_metadata_t {
    bit<16>  remaining;
}



struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    ipv4_option_t      ipv4_option;
    mri_t              mri;
    switch_t[MAX_HOPS] swtraces;
}

/*
    The original idea was to make this structure as?
    struct telemetry_meta_t{
        mri_t              mri;
        switch_t[MAX_HOPS] swtraces;
    }
    but the compiler was throwing bugs like nested struct and nested stack
    so the following is used
*/
struct telemetry_meta_t{

    bit<16>   count;       

    uint_16   swid1;           
    uint_32   qdepth1;         
    uint_32   timestamp1;       
    uint_32   timedelta1;      
    uint_16   rule_id1;        

    uint_16   swid2;           
    uint_32   qdepth2;         
    uint_32   timestamp2;       
    uint_32   timedelta2;      
    uint_16   rule_id2;        

    uint_16   swid3;           
    uint_32   qdepth3;         
    uint_32   timestamp3;       
    uint_32   timedelta3;      
    uint_16   rule_id3;        

    uint_16   swid4;           
    uint_32   qdepth4;         
    uint_32   timestamp4;       
    uint_32   timedelta4;      
    uint_16   rule_id4;        

    uint_16   swid5;           
    uint_32   qdepth5;         
    uint_32   timestamp5;       
    uint_32   timedelta5;      
    uint_16   rule_id5;        

    uint_16   swid6;           
    uint_32   qdepth6;         
    uint_32   timestamp6;       
    uint_32   timedelta6;      
    uint_16   rule_id6;        

    uint_16   swid7;           
    uint_32   qdepth7;         
    uint_32   timestamp7;       
    uint_32   timedelta7;      
    uint_16   rule_id7;  

    uint_16   swid8;           
    uint_32   qdepth8;         
    uint_32   timestamp8;       
    uint_32   timedelta8;      
    uint_16   rule_id8;       

}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t    parser_metadata;
    telemetry_meta_t     telemetry_metadata;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
            5             : accept;
            default       : parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option) {
            IPV4_OPTION_MRI: parse_mri;
            default: accept;
        }
    }

    state parse_mri {
        packet.extract(hdr.mri);
        meta.parser_metadata.remaining = hdr.mri.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swtrace;
        }
    }

    state parse_swtrace {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swtrace;
        }
    }    
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, uint_16 ruleId, bit<1> lastHop) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.ingress_metadata.rule_id = ruleId;
        meta.ingress_metadata.last_hop = lastHop;
        
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    action set_options(){
        hdr.ipv4_option.setValid();
        hdr.ipv4_option.option = IPV4_OPTION_MRI;
        hdr.ipv4_option.optionLength = 2; // 1 (copyFlag) + 2 (optClass) + 5 (option) + 8 (optionLength) = 16 bits = 2 bytes
        hdr.ipv4_option.optClass = 2; // "0" -> control; "2" -> debug and measurements; "1" and "3" are reserved
        hdr.ipv4_option.copyFlag = 0; // It is not necessary to copy for each fragment

        hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
    }

    action set_mri(){
        hdr.mri.setValid();
        hdr.mri.count = 0;
    }

    apply {

        if (!hdr.ipv4_option.isValid()){
            set_options();
        }
        if (!hdr.mri.isValid() && hdr.ipv4.dstAddr != STATS_CONTROLLER_IPV4) {
            set_mri();
            hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 2; 
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
        }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action add_swtrace(uint_16 swid) { 
        hdr.mri.count = hdr.mri.count + 1;
        hdr.swtraces.push_front(1);
        // According to the P4_16 spec, pushed elements are invalid, so we need
        // to call setValid(). Older bmv2 versions would mark the new header(s)
        // valid automatically (P4_14 behavior), but starting with version 1.11,
        // bmv2 conforms with the P4_16 spec.
        hdr.swtraces[0].setValid();
        hdr.swtraces[0].swid = swid;
        hdr.swtraces[0].qdepth = (uint_32)standard_metadata.deq_qdepth;
        hdr.swtraces[0].timestamp = (uint_32)standard_metadata.enq_timestamp;
        hdr.swtraces[0].timedelta = (uint_32) standard_metadata.deq_timedelta;
        hdr.swtraces[0].rule_id = meta.ingress_metadata.rule_id;

        hdr.ipv4.ihl = hdr.ipv4.ihl + 4;
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 16; 
	    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
    }

    table swtrace {
        actions = { 
	    add_swtrace; 
	    NoAction; 
        }
        default_action = NoAction();      
    }
    
    
    //Used to recalculate the size of the packet when the telemetry headers are removed
    action recalculate_size(){
        hdr.ipv4.ihl = 5;
        hdr.ipv4_option.optionLength = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - hdr.mri.count * 16 - 4;
    }

    action invalidate_telemetry_headers(){
        
        // Ipv4_options and mri invalidation
        hdr.mri.setInvalid();
        hdr.ipv4_option.setInvalid();

        // swtrace invalidation
        hdr.swtraces[0].setInvalid();
        hdr.swtraces[1].setInvalid();
        hdr.swtraces[2].setInvalid();
        hdr.swtraces[3].setInvalid();
        hdr.swtraces[4].setInvalid();
        hdr.swtraces[5].setInvalid();
        hdr.swtraces[6].setInvalid();
        hdr.swtraces[7].setInvalid();
        hdr.swtraces[8].setInvalid();
    }

    action copy_telemetry_to_meta(){
        meta.telemetry_metadata.count = hdr.mri.count;
        
        
        meta.telemetry_metadata.swid1 = hdr.swtraces[0].swid;
        meta.telemetry_metadata.qdepth1 = hdr.swtraces[0].qdepth;
        meta.telemetry_metadata.timestamp1 = hdr.swtraces[0].timestamp;
        meta.telemetry_metadata.timedelta1 = hdr.swtraces[0].timedelta;
        meta.telemetry_metadata.rule_id1 = hdr.swtraces[0].rule_id;

        if (hdr.mri.count > 1){
            meta.telemetry_metadata.swid2 = hdr.swtraces[1].swid;
            meta.telemetry_metadata.qdepth2 = hdr.swtraces[1].qdepth;
            meta.telemetry_metadata.timestamp2 = hdr.swtraces[1].timestamp;
            meta.telemetry_metadata.timedelta2 = hdr.swtraces[1].timedelta;
            meta.telemetry_metadata.rule_id2 = hdr.swtraces[1].rule_id;


        }

    }


    action do_clone(uint_32 session_id){
        clone3(CloneType.E2E, session_id, {standard_metadata, meta});
    }

    table clone_session {
        actions = {
            do_clone;
            NoAction;
        }
        default_action = NoAction();
    }
    
    action set_option(){
        hdr.ipv4_option.setValid();
        hdr.ipv4_option.option = IPV4_OPTION_MRI;
        hdr.ipv4_option.optClass = 2; // "0" -> control; "2" -> debug and measurements; "1" and "3" are reserved
        hdr.ipv4_option.copyFlag = 0; // It is not necessary to copy for each fragment
    }

    action set_mri(){
        hdr.mri.setValid();
        hdr.mri.count = meta.telemetry_metadata.count;
    }

    action push_trace(){
        hdr.swtraces.push_front(1);
        hdr.swtraces[0].setValid();

    }
    action set_traces(){

        push_trace();
        hdr.swtraces[0].swid = meta.telemetry_metadata.swid1;
        hdr.swtraces[0].qdepth = meta.telemetry_metadata.qdepth1;
        hdr.swtraces[0].timestamp = meta.telemetry_metadata.timestamp1;
        hdr.swtraces[0].timedelta = meta.telemetry_metadata.timedelta1;
        hdr.swtraces[0].rule_id = meta.telemetry_metadata.rule_id1;
        
        hdr.swtraces[1].setValid();
        if (hdr.mri.count > 1){
            hdr.swtraces[1].swid = meta.telemetry_metadata.swid2;
            hdr.swtraces[1].qdepth = meta.telemetry_metadata.qdepth2;
            hdr.swtraces[1].timestamp = meta.telemetry_metadata.timestamp2;
            hdr.swtraces[1].timedelta = meta.telemetry_metadata.timedelta2;
            hdr.swtraces[1].rule_id = meta.telemetry_metadata.rule_id2;
        }
    }

    action restore_telemetry_hdrs(){
        
        set_option();
        set_mri();
        set_traces();
        
    }

    action restore_pkt_size(){
        //each switch trace contains 16 bytes so the new ihl will be:
        // 5 (ipv4 fix fields) + 
        // <number of traces> * 4 (traces) + 
        //1 (16 bits -> counter of traces; 16 bits -> option fields)
        hdr.ipv4.ihl = 5 + (bit<4>)hdr.mri.count * 4 + 1;
        
        //the option size in bytes is:
        // 2 (1b -> copyFlag; 2b->optClass; 5b-> option; 8b-> optionLength) + 
        // 2 (traces counter has 16 bits) + 
        // 16 * hdr.mri.count
        hdr.ipv4_option.optionLength = 2 + 2 + (bit<8>)hdr.mri.count * 16;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)hdr.ipv4_option.optionLength;
    }
    
    action redirect_to_stat(){
        hdr.ipv4.dstAddr = STATS_CONTROLLER_IPV4;
    }

    apply {
        
        if (IS_E2E_CLONE(standard_metadata)){
            //1) Restore telemetry headers
            restore_telemetry_hdrs();
            //2) Restore packet size
            restore_pkt_size();
            //3) redirect to stat
            redirect_to_stat();

        }
        else{
            if (hdr.mri.isValid() && hdr.ipv4.dstAddr != STATS_CONTROLLER_IPV4){
                //1) apply swtrace
                swtrace.apply();
                if (meta.ingress_metadata.last_hop == 1 ){
                    //2) copy telemetry headers to metadata
                    copy_telemetry_to_meta();
                    //3) recalculate packet size
                    recalculate_size();
                    //4) invalidate telemetry headers
                    invalidate_telemetry_headers();
                    //5) clone packet keeping metadata
                    clone_session.apply();
                }

            }
        }
        
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.mri);
        packet.emit(hdr.swtraces);
                         
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
