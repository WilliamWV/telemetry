/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MRI  = 0x6041;
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
    bit<16>  toParse;
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
    mri_t              mri;
    switch_t[MAX_HOPS] swtraces;
    ipv4_t             ipv4;
    ipv4_option_t      ipv4_option;
    
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

    uint_16   swid0;           
    uint_32   qdepth0;         
    uint_32   timestamp0;       
    uint_32   timedelta0;      
    uint_16   rule_id0;        

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
            TYPE_MRI: parse_mri;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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
        meta.parser_metadata.remaining = hdr.mri.toParse;
        transition select(meta.parser_metadata.remaining) {
            0 : parse_ipv4;
            default: parse_swtrace;
        }
    }

    state parse_swtrace {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : parse_ipv4;
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
    
    action set_mri(){
        hdr.mri.setValid();
        hdr.mri.count = 0;
        hdr.mri.toParse = 0;
        hdr.ethernet.etherType = TYPE_MRI;
    }

    apply {

        if (!hdr.mri.isValid() && hdr.ipv4.dstAddr != STATS_CONTROLLER_IPV4) {
            set_mri();
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
        hdr.mri.toParse = hdr.mri.toParse + 1;
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

    }

    table swtrace {
        actions = { 
	    add_swtrace; 
	    NoAction; 
        }
        default_action = NoAction();      
    }
    
    
    
    action invalidate_telemetry_headers(){
        
        // Ipv4_options and mri invalidation
        hdr.mri.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
    
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
        
        if (hdr.mri.count > 0){
            meta.telemetry_metadata.swid0 = hdr.swtraces[0].swid;
            meta.telemetry_metadata.qdepth0 = hdr.swtraces[0].qdepth;
            meta.telemetry_metadata.timestamp0 = hdr.swtraces[0].timestamp;
            meta.telemetry_metadata.timedelta0 = hdr.swtraces[0].timedelta;
            meta.telemetry_metadata.rule_id0 = hdr.swtraces[0].rule_id;
        }
        if (hdr.mri.count > 1){
            meta.telemetry_metadata.swid1 = hdr.swtraces[1].swid;
            meta.telemetry_metadata.qdepth1 = hdr.swtraces[1].qdepth;
            meta.telemetry_metadata.timestamp1 = hdr.swtraces[1].timestamp;
            meta.telemetry_metadata.timedelta1 = hdr.swtraces[1].timedelta;
            meta.telemetry_metadata.rule_id1 = hdr.swtraces[1].rule_id;
        }
        if (hdr.mri.count > 2){
            meta.telemetry_metadata.swid2 = hdr.swtraces[2].swid;
            meta.telemetry_metadata.qdepth2 = hdr.swtraces[2].qdepth;
            meta.telemetry_metadata.timestamp2 = hdr.swtraces[2].timestamp;
            meta.telemetry_metadata.timedelta2 = hdr.swtraces[2].timedelta;
            meta.telemetry_metadata.rule_id2 = hdr.swtraces[2].rule_id;
        }
        if (hdr.mri.count > 3){
            meta.telemetry_metadata.swid3 = hdr.swtraces[3].swid;
            meta.telemetry_metadata.qdepth3 = hdr.swtraces[3].qdepth;
            meta.telemetry_metadata.timestamp3 = hdr.swtraces[3].timestamp;
            meta.telemetry_metadata.timedelta3 = hdr.swtraces[3].timedelta;
            meta.telemetry_metadata.rule_id3 = hdr.swtraces[3].rule_id;
        }
        if (hdr.mri.count > 4){
            meta.telemetry_metadata.swid4 = hdr.swtraces[4].swid;
            meta.telemetry_metadata.qdepth4 = hdr.swtraces[4].qdepth;
            meta.telemetry_metadata.timestamp4 = hdr.swtraces[4].timestamp;
            meta.telemetry_metadata.timedelta4 = hdr.swtraces[4].timedelta;
            meta.telemetry_metadata.rule_id4 = hdr.swtraces[4].rule_id;
        }
        if (hdr.mri.count > 5){
            meta.telemetry_metadata.swid5 = hdr.swtraces[5].swid;
            meta.telemetry_metadata.qdepth5 = hdr.swtraces[5].qdepth;
            meta.telemetry_metadata.timestamp5 = hdr.swtraces[5].timestamp;
            meta.telemetry_metadata.timedelta5 = hdr.swtraces[5].timedelta;
            meta.telemetry_metadata.rule_id5 = hdr.swtraces[5].rule_id;
        }
        if (hdr.mri.count > 6){
            meta.telemetry_metadata.swid6 = hdr.swtraces[6].swid;
            meta.telemetry_metadata.qdepth6 = hdr.swtraces[6].qdepth;
            meta.telemetry_metadata.timestamp6 = hdr.swtraces[6].timestamp;
            meta.telemetry_metadata.timedelta6 = hdr.swtraces[6].timedelta;
            meta.telemetry_metadata.rule_id6 = hdr.swtraces[6].rule_id;
        }
        if (hdr.mri.count > 7){
            meta.telemetry_metadata.swid7 = hdr.swtraces[7].swid;
            meta.telemetry_metadata.qdepth7 = hdr.swtraces[7].qdepth;
            meta.telemetry_metadata.timestamp7 = hdr.swtraces[7].timestamp;
            meta.telemetry_metadata.timedelta7 = hdr.swtraces[7].timedelta;
            meta.telemetry_metadata.rule_id7 = hdr.swtraces[7].rule_id;
        }
        if (hdr.mri.count > 8){
            meta.telemetry_metadata.swid8 = hdr.swtraces[8].swid;
            meta.telemetry_metadata.qdepth8 = hdr.swtraces[8].qdepth;
            meta.telemetry_metadata.timestamp8 = hdr.swtraces[8].timestamp;
            meta.telemetry_metadata.timedelta8 = hdr.swtraces[8].timedelta;
            meta.telemetry_metadata.rule_id8 = hdr.swtraces[8].rule_id;
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
    
    
    action set_mri(){
        hdr.mri.setValid();
        hdr.ethernet.etherType = TYPE_MRI;
        hdr.mri.count = meta.telemetry_metadata.count;
        hdr.mri.toParse = MAX_HOPS;
    }

    action set_traces(){

        hdr.swtraces[0].setValid();
        if (hdr.mri.count > 0){

            hdr.swtraces[0].swid = meta.telemetry_metadata.swid0;
            hdr.swtraces[0].qdepth = meta.telemetry_metadata.qdepth0;
            hdr.swtraces[0].timestamp = meta.telemetry_metadata.timestamp0;
            hdr.swtraces[0].timedelta = meta.telemetry_metadata.timedelta0;
            hdr.swtraces[0].rule_id = meta.telemetry_metadata.rule_id0;
        }
        hdr.swtraces[1].setValid();
        if (hdr.mri.count > 1){
            
            hdr.swtraces[1].swid = meta.telemetry_metadata.swid1;
            hdr.swtraces[1].qdepth = meta.telemetry_metadata.qdepth1;
            hdr.swtraces[1].timestamp = meta.telemetry_metadata.timestamp1;
            hdr.swtraces[1].timedelta = meta.telemetry_metadata.timedelta1;
            hdr.swtraces[1].rule_id = meta.telemetry_metadata.rule_id1;
        }
        hdr.swtraces[2].setValid();
        if (hdr.mri.count > 2){
            
            hdr.swtraces[2].swid = meta.telemetry_metadata.swid2;
            hdr.swtraces[2].qdepth = meta.telemetry_metadata.qdepth2;
            hdr.swtraces[2].timestamp = meta.telemetry_metadata.timestamp2;
            hdr.swtraces[2].timedelta = meta.telemetry_metadata.timedelta2;
            hdr.swtraces[2].rule_id = meta.telemetry_metadata.rule_id2;
        }
        hdr.swtraces[3].setValid();
        if (hdr.mri.count > 3){
            
            hdr.swtraces[3].swid = meta.telemetry_metadata.swid3;
            hdr.swtraces[3].qdepth = meta.telemetry_metadata.qdepth3;
            hdr.swtraces[3].timestamp = meta.telemetry_metadata.timestamp3;
            hdr.swtraces[3].timedelta = meta.telemetry_metadata.timedelta3;
            hdr.swtraces[3].rule_id = meta.telemetry_metadata.rule_id3;
        }
        hdr.swtraces[4].setValid();
        if (hdr.mri.count > 4){
            
            hdr.swtraces[4].swid = meta.telemetry_metadata.swid4;
            hdr.swtraces[4].qdepth = meta.telemetry_metadata.qdepth4;
            hdr.swtraces[4].timestamp = meta.telemetry_metadata.timestamp4;
            hdr.swtraces[4].timedelta = meta.telemetry_metadata.timedelta4;
            hdr.swtraces[4].rule_id = meta.telemetry_metadata.rule_id4;
        }
        hdr.swtraces[5].setValid();
        if (hdr.mri.count > 5){
            
            hdr.swtraces[5].swid = meta.telemetry_metadata.swid5;
            hdr.swtraces[5].qdepth = meta.telemetry_metadata.qdepth5;
            hdr.swtraces[5].timestamp = meta.telemetry_metadata.timestamp5;
            hdr.swtraces[5].timedelta = meta.telemetry_metadata.timedelta5;
            hdr.swtraces[5].rule_id = meta.telemetry_metadata.rule_id5;
        }
        hdr.swtraces[6].setValid();
        if (hdr.mri.count > 6){
            
            hdr.swtraces[6].swid = meta.telemetry_metadata.swid6;
            hdr.swtraces[6].qdepth = meta.telemetry_metadata.qdepth6;
            hdr.swtraces[6].timestamp = meta.telemetry_metadata.timestamp6;
            hdr.swtraces[6].timedelta = meta.telemetry_metadata.timedelta6;
            hdr.swtraces[6].rule_id = meta.telemetry_metadata.rule_id6;
        }
        hdr.swtraces[7].setValid();
        if (hdr.mri.count > 7){
            
            hdr.swtraces[7].swid = meta.telemetry_metadata.swid7;
            hdr.swtraces[7].qdepth = meta.telemetry_metadata.qdepth7;
            hdr.swtraces[7].timestamp = meta.telemetry_metadata.timestamp7;
            hdr.swtraces[7].timedelta = meta.telemetry_metadata.timedelta7;
            hdr.swtraces[7].rule_id = meta.telemetry_metadata.rule_id7;
        }
        hdr.swtraces[8].setValid();
        if (hdr.mri.count > 8){
            
            hdr.swtraces[8].swid = meta.telemetry_metadata.swid8;
            hdr.swtraces[8].qdepth = meta.telemetry_metadata.qdepth8;
            hdr.swtraces[8].timestamp = meta.telemetry_metadata.timestamp8;
            hdr.swtraces[8].timedelta = meta.telemetry_metadata.timedelta8;
            hdr.swtraces[8].rule_id = meta.telemetry_metadata.rule_id8;
        }


    }

    action restore_telemetry_hdrs(){
        
        set_mri();
        set_traces();
        
    }

    
    action redirect_to_stat(){
        hdr.ipv4.dstAddr = STATS_CONTROLLER_IPV4;
    }

    apply {
        
        if (IS_E2E_CLONE(standard_metadata)){
            //1) Restore telemetry headers
            restore_telemetry_hdrs();
            //2) redirect to stat
            redirect_to_stat();

        }
        else{
            if (hdr.mri.isValid() && hdr.ipv4.dstAddr != STATS_CONTROLLER_IPV4){
                //1) apply swtrace
                swtrace.apply();
                if (meta.ingress_metadata.last_hop == 1 ){
                    //2) copy telemetry headers to metadata
                    copy_telemetry_to_meta();
                    //3) invalidate telemetry headers
                    invalidate_telemetry_headers();
                    //4) clone packet keeping metadata
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
        packet.emit(hdr.mri);
        packet.emit(hdr.swtraces);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        
                         
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
