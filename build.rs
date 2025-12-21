use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        use_cls:{
            all(any(feature="cls_sync",feature="cls_async"),not(any(feature="std_sync",feature="std_async")))
        },
        use_std:{
            all(any(feature="std_sync",feature="cls_sync"),not(any(feature = "cls_sync",feature="cls_async")))
        },
        sync:{
            any(feature = "std_sync",feature="cls_sync")
        },
        aync:{
            any(feature = "std_async",feature="cls_async")
        },
        cls_sync:{
            all(feature = "cls_sync",not(any(feature="std_sync",feature="std_async")))
        },
        cls_async:{
            all(feature = "cls_async",not(any(feature="std_sync",feature="std_async")))
        },
        std_sync:{
            all(feature = "std_sync",not(any(feature="cls_sync",feature="cls_async")))
        },
        std_async:{
            all(feature = "std_async",not(any(feature="cls_sync",feature="cls_async")))
        }

    }
}