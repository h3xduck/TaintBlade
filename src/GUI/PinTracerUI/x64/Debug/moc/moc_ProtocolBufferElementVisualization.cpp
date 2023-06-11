/****************************************************************************
** Meta object code from reading C++ file 'ProtocolBufferElementVisualization.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../include/widgets/protocol/ProtocolBufferElementVisualization.h"
#include <QtCore/qmetatype.h>

#if __has_include(<QtCore/qtmochelpers.h>)
#include <QtCore/qtmochelpers.h>
#else
QT_BEGIN_MOC_NAMESPACE
#endif


#include <memory>

#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ProtocolBufferElementVisualization.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {

#ifdef QT_MOC_HAS_STRINGDATA
struct qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t {};
static constexpr auto qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS = QtMocHelpers::stringData(
    "ProtocolBufferElementVisualization",
    "onPointedByteHighlighButtonClicked",
    "",
    "byteOffset",
    "showTreeWidgetContextMenu",
    "point",
    "QTreeWidget*",
    "treeWidget",
    "buttonRequestHighlightPointedToByte",
    "sendRequestShowTreeWidgetContextMenu"
);
#else  // !QT_MOC_HAS_STRING_DATA
struct qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t {
    uint offsetsAndSizes[20];
    char stringdata0[35];
    char stringdata1[35];
    char stringdata2[1];
    char stringdata3[11];
    char stringdata4[26];
    char stringdata5[6];
    char stringdata6[13];
    char stringdata7[11];
    char stringdata8[36];
    char stringdata9[37];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS = {
    {
        QT_MOC_LITERAL(0, 34),  // "ProtocolBufferElementVisualiz..."
        QT_MOC_LITERAL(35, 34),  // "onPointedByteHighlighButtonCl..."
        QT_MOC_LITERAL(70, 0),  // ""
        QT_MOC_LITERAL(71, 10),  // "byteOffset"
        QT_MOC_LITERAL(82, 25),  // "showTreeWidgetContextMenu"
        QT_MOC_LITERAL(108, 5),  // "point"
        QT_MOC_LITERAL(114, 12),  // "QTreeWidget*"
        QT_MOC_LITERAL(127, 10),  // "treeWidget"
        QT_MOC_LITERAL(138, 35),  // "buttonRequestHighlightPointed..."
        QT_MOC_LITERAL(174, 36)   // "sendRequestShowTreeWidgetCont..."
    },
    "ProtocolBufferElementVisualization",
    "onPointedByteHighlighButtonClicked",
    "",
    "byteOffset",
    "showTreeWidgetContextMenu",
    "point",
    "QTreeWidget*",
    "treeWidget",
    "buttonRequestHighlightPointedToByte",
    "sendRequestShowTreeWidgetContextMenu"
};
#undef QT_MOC_LITERAL
#endif // !QT_MOC_HAS_STRING_DATA
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_CLASSProtocolBufferElementVisualizationENDCLASS[] = {

 // content:
      11,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   38,    2, 0x06,    1 /* Public */,
       4,    2,   41,    2, 0x06,    3 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       8,    0,   46,    2, 0x08,    6 /* Private */,
       9,    1,   47,    2, 0x08,    7 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::QPoint, 0x80000000 | 6,    5,    7,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QPoint,    5,

       0        // eod
};

Q_CONSTINIT const QMetaObject ProtocolBufferElementVisualization::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS.offsetsAndSizes,
    qt_meta_data_CLASSProtocolBufferElementVisualizationENDCLASS,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<ProtocolBufferElementVisualization, std::true_type>,
        // method 'onPointedByteHighlighButtonClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'showTreeWidgetContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QPoint &, std::false_type>,
        QtPrivate::TypeAndForceComplete<QTreeWidget *, std::false_type>,
        // method 'buttonRequestHighlightPointedToByte'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'sendRequestShowTreeWidgetContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QPoint &, std::false_type>
    >,
    nullptr
} };

void ProtocolBufferElementVisualization::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ProtocolBufferElementVisualization *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->onPointedByteHighlighButtonClicked((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 1: _t->showTreeWidgetContextMenu((*reinterpret_cast< std::add_pointer_t<QPoint>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QTreeWidget*>>(_a[2]))); break;
        case 2: _t->buttonRequestHighlightPointedToByte(); break;
        case 3: _t->sendRequestShowTreeWidgetContextMenu((*reinterpret_cast< std::add_pointer_t<QPoint>>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ProtocolBufferElementVisualization::*)(int );
            if (_t _q_method = &ProtocolBufferElementVisualization::onPointedByteHighlighButtonClicked; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ProtocolBufferElementVisualization::*)(const QPoint & , QTreeWidget * );
            if (_t _q_method = &ProtocolBufferElementVisualization::showTreeWidgetContextMenu; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
    }
}

const QMetaObject *ProtocolBufferElementVisualization::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProtocolBufferElementVisualization::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int ProtocolBufferElementVisualization::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 4)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 4;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 4)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 4;
    }
    return _id;
}

// SIGNAL 0
void ProtocolBufferElementVisualization::onPointedByteHighlighButtonClicked(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void ProtocolBufferElementVisualization::showTreeWidgetContextMenu(const QPoint & _t1, QTreeWidget * _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
